#include "kfeature.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#ifdef LINUX
#include <sys/sendfile.h>
#endif
#ifdef BSD_OS
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <sys/uio.h>
#endif
#include "kselectable.h"
#include "ksocket.h"
#include "kmalloc.h"
#include "kfiber.h"
#include "klist.h"
#include "kudp.h"

#ifdef KSOCKET_SSL
static inline int kgl_ssl_writev(kssl_session* ssl, WSABUF* buffer, int bc)
{
	int got = 0;
	for (int i = 0; i < bc; i++) {
		char* hot = (char*)buffer[i].iov_base;
		int len = buffer[i].iov_len;
		while (len > 0) {
#ifdef ENABLE_KSSL_BIO
			//ssl bio max write 64KB
			int left = 65536 - got;
			if (left <= 0) {
				return got;
			}
			len = KGL_MIN(left, len);
#endif
#ifdef SSL_READ_EARLY_DATA_SUCCESS
			if (ssl->in_early) {
				//printf("ssl_is_init_finished=[%d]\n", SSL_is_init_finished(ssl->ssl));
				size_t write_bytes;
				int n = SSL_write_early_data(ssl->ssl, hot, len, &write_bytes);
				if (n > 0) {
					got += (int)write_bytes;
					len -= (int)write_bytes;
					hot += (int)write_bytes;
					//printf("SSL_write_early_data try write=[%d] return [%d] got=[%d].\n", len, write_bytes, got);
					continue;
				}
				return (got > 0 ? got : -1);
			}
#endif
			int this_len = SSL_write(ssl->ssl, hot, len);
			//printf("SSL_write try write=[%d] return [%d] got=[%d].\n", len,this_len,got);
			if (this_len != len) {
				return this_len > 0 ? got + this_len : (got > 0 ? got : this_len);
			}
			got += this_len;
			break;
		}
	}
	return got;
}
static inline int kgl_ssl_readv(kssl_session* ssl, kgl_iovec* buffer, int bc)
{
	int got = 0;
	for (int i = 0; i < bc; i++) {
		u_char* hot = (u_char*)buffer[i].iov_base;
		int len = buffer[i].iov_len;
		while (len > 0) {
#ifdef SSL_READ_EARLY_DATA_SUCCESS
			if (ssl->early_preread) {
				ssl->early_preread = 0;
				got += 1;
				*hot = ssl->early_buf;
				hot++;
				len--;
				continue;
			}
			if (ssl->in_early) {
				size_t read_bytes = 0;
				int n = SSL_read_early_data(ssl->ssl, hot, len, &read_bytes);
				//printf("ssl_read_early_data ret=[%d] read_bytes=[%d]\n", n, read_bytes);
				if (n == SSL_READ_EARLY_DATA_FINISH) {
					ssl->in_early = 0;
					continue;
				}
				if (n != SSL_READ_EARLY_DATA_SUCCESS) {
					return got;
				}
				got += (int)read_bytes;
				len -= (int)read_bytes;
				hot += (int)read_bytes;
				continue;
			}
#endif
			int this_len = SSL_read(ssl->ssl, hot, len);
			if (this_len != len) {
				return this_len > 0 ? got + this_len : (got>0?got:this_len);
			}
			got += this_len;
			break;
		}
	}
	return got;
}
#endif
#ifdef HAVE_WRITEV
#define kgl_writev writev
#else
#ifndef _WIN32
#error "If you be sure that system has no writev/readv please remove this line"
#endif
static inline int kgl_writev(SOCKET s, kgl_iovec * buffer, int bc)
{
	int got = 0;
	for (int i = 0; i < bc; i++) {
		int this_len = send(s, buffer[i].iov_base, buffer[i].iov_len, 0);
		if (this_len != (int)buffer[i].iov_len) {
			return this_len > 0 ? got + this_len : (got > 0 ? got : this_len);
		}
		got += this_len;
	}
	return got;
}
#endif
#ifdef HAVE_READV
#define kgl_readv readv
#else
static inline int kgl_readv(SOCKET s, kgl_iovec* buffer, int bc)
{
	int got = 0;
	for (int i = 0; i < bc; i++) {
		int this_len = recv(s, buffer[i].iov_base, buffer[i].iov_len, 0);
		if (this_len != (int)buffer[i].iov_len) {
			return this_len > 0 ? got + this_len : (got > 0 ? got : this_len);
		}
		got += this_len;
	}
	return got;
}
#endif
void selectable_clean(kselectable* st)
{
	/* aio file type do not call selectable_clean */
	kassert(KBIT_TEST(st->base.st_flags, STF_LOCK|STF_AIO_FILE) == 0);
	kassert(st->base.queue.next == NULL);
	kassert(st->base.queue.prev == NULL);
	if (ksocket_opened(st->fd)) {
		if (st->base.selector) {
			selectable_remove(st);
		}
		ksocket_shutdown(st->fd, SHUT_RDWR);
		ksocket_close(st->fd);
	}
#ifdef KSOCKET_SSL
	if (st->ssl) {
		SSL_free(st->ssl->ssl);
#ifdef ENABLE_KSSL_BIO
#endif
		xfree(st->ssl);
	}
#endif
}
#ifndef _WIN32
int selectable_recvmsg(kselectable* st)
{
	kconnection* c = kgl_list_data(st, kconnection, st);
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (struct sockaddr*)&c->addr;
	msg.msg_namelen = ksocket_addr_len((sockaddr_i *)msg.msg_name);
	msg.msg_iov = (struct iovec *)st->e[OP_READ].buffer->iov_base;
	msg.msg_iovlen = st->e[OP_READ].buffer->iov_len;
	msg.msg_control = c->udp->pktinfo;
	if (c->udp) {
		memset(c->udp, 0, sizeof(kudp_extend));
		msg.msg_controllen = sizeof(c->udp->pktinfo);
	}
	return recvmsg(st->fd, &msg, 0);
}
#endif
static inline kev_result selectable_udp_read_event(kselectable* st, result_callback result, buffer_callback buffer, void* arg)
{
#ifndef _WIN32
	assert(KBIT_TEST(st->base.st_flags, STF_UDP));
	int got = selectable_recvmsg(st);
	if (got>=0) {
		return result(st->data, arg, got);
	}
	switch(errno) {
	case EAGAIN:
	case EINTR:
		KBIT_CLR(st->base.st_flags, STF_RREADY);
		return kgl_selector_module.read(st->base.selector, st, result, buffer, arg);
	case ENOMEM:
		return result(st->data, arg, ST_ERR_NOMEM);
	default:
		return result(st->data, arg, ST_ERR_RESULT);
	}
#else
	//windows iocp never goto here.
	assert(false);
	return kev_err;
#endif
}

#ifdef ENABLE_KSSL_BIO
static kev_result selectable_ssl_read(kselectable* st, result_callback result, buffer_callback buffer, void* arg) {
	kssl_bio* ssl_bio = &st->ssl->bio[OP_READ];
	ssl_bio->buffer = buffer;
	ssl_bio->result = result;
	ssl_bio->arg = arg;
	ssl_bio->st = st;
	kassert(result != result_ssl_bio_read);
	kassert(arg != ssl_bio);
	if (BIO_pending(ssl_bio->bio) > 0) {
		kassert(!KBIT_TEST(st->base.st_flags, STF_READ));
		//ssl still have data to read
		st->e[OP_READ].arg = arg;
		st->e[OP_READ].result = result;
		st->e[OP_READ].buffer = buffer;
		KBIT_SET(st->base.st_flags, STF_READ | STF_RREADY2);
		KBIT_CLR(st->base.st_flags, STF_RDHUP);
		return kselectable_is_read_ready(st->base.selector, st);
	}
	kssl_bio_buffer* bio_buffer = (kssl_bio_buffer*)xmalloc(sizeof(kssl_bio_buffer));
	bio_buffer->bio = ssl_bio;
	buffer_ssl_bio_read(bio_buffer);
	return kgl_selector_module.read(st->base.selector, st, result_ssl_bio_read, bio_buffer->buf, bio_buffer);
}
static kev_result selectable_ssl_write(kselectable* st, result_callback result, buffer_callback buffer, void* arg) {
	kssl_bio* ssl_bio = &st->ssl->bio[OP_WRITE];
	ssl_bio->got = 0;
	if (buffer) {
		ssl_bio->got = kgl_ssl_writev(st->ssl, (kgl_iovec*)buffer->iov_base, buffer->iov_len);
	}
	if (BIO_pending(ssl_bio->bio) <= 0) {
		st->e[OP_WRITE].arg = arg;
		st->e[OP_WRITE].result = result;
		st->e[OP_WRITE].buffer = buffer;
		KBIT_SET(st->base.st_flags, STF_WRITE | STF_WREADY2);
		return kselectable_is_write_ready(st->base.selector, st);
	}
	ssl_bio->buffer = buffer;
	ssl_bio->result = result;
	ssl_bio->arg = arg;
	ssl_bio->st = st;

	kssl_bio_buffer* bio_buffer = (kssl_bio_buffer*)xmalloc(sizeof(kssl_bio_buffer));
	bio_buffer->bio = ssl_bio;
	buffer_ssl_bio_write(bio_buffer);
	return kgl_selector_module.write(st->base.selector, st, result_ssl_bio_write, bio_buffer->buf, bio_buffer);
}

static inline kev_result selectable_low_event_write(kselectable* st, result_callback result, buffer_callback buffer, void* arg) {
#ifdef _WIN32
	kassert(false);
#endif
	if (unlikely(buffer == NULL)) {
		return result(st->data, arg, 0);
	}
	assert(buffer->iov_base);
	int got = kgl_writev(st->fd, (kgl_iovec *)buffer->iov_base, buffer->iov_len);
	if (got >= 0) {
		return result(st->data, arg, got);
	}
	if (errno == EAGAIN) {
		KBIT_CLR(st->base.st_flags, STF_WREADY);
		return kgl_selector_module.write(st->base.selector, st, result, buffer, arg);

	}
	return result(st->data, arg, got);
}
static inline kev_result selectable_low_event_read(kselectable* st, result_callback result, buffer_callback buffer, void* arg) {
#ifdef _WIN32
	kassert(false);
#endif
	if (unlikely(buffer == NULL)) {
		return result(st->data, arg, 0);
	}
	int got = kgl_readv(st->fd, (kgl_iovec*)buffer->iov_base, buffer->iov_len);
	if (got >= 0) {
		return result(st->data, arg, got);
	}
	if (errno == EAGAIN) {
		KBIT_CLR(st->base.st_flags, STF_RREADY);
		return kgl_selector_module.read(st->base.selector, st, result, buffer, arg);
	}
	return result(st->data, arg, got);
}
#endif
#ifndef _WIN32
static inline kev_result selectable_event_sendfile(kselectable* st, result_callback result, buffer_callback buffer, void* arg) {
	kasync_file* file = (kasync_file*)buffer->iov_base;
	off_t offset = file->st.offset;
	assert(sizeof(off_t) == sizeof(int64_t));
	int got = -1;
#ifdef KSOCKET_SSL
#ifdef LINUX_IOURING
	//linux iouring sendfile without ssl do not goto here.
	assert(st->ssl);
#endif
	if (st->ssl) {
		assert(kgl_ssl_support_sendfile(st->ssl));
#if defined(BIO_get_ktls_send)
		got = SSL_sendfile(st->ssl->ssl, file->st.fd, offset, buffer->iov_len, 0);
		if (got >= 0) {
			return result(st->data, arg, got);
		}
		int err = SSL_get_error(st->ssl->ssl, got);
		if (err == SSL_ERROR_WANT_WRITE) {
			KBIT_CLR(st->base.st_flags, STF_WREADY);
			return kgl_selector_module.sendfile(st, result, buffer, arg);
		}
#endif
		return result(st->data, arg, got);
	}
#endif

#ifdef LINUX
	got = sendfile(st->fd, file->st.fd, &offset, buffer->iov_len);
	if (got >= 0) {
		return result(st->data, arg, got);
	}
	if (errno == EAGAIN) {
		KBIT_CLR(st->base.st_flags, STF_WREADY);
		return kgl_selector_module.sendfile(st, result, buffer, arg);
	}
	return result(st->data, arg, got);
#elif BSD_OS
#ifdef DARWIN
	off_t send_bytes = buffer->iov_len;
	got = sendfile(file->st.fd, st->fd, offset, &send_bytes, NULL, 0);
#else
	off_t send_bytes = 0;
	got = sendfile(file->st.fd, st->fd, offset, buffer->iov_len, NULL, &send_bytes, 0);
#endif
	if (got < 0) {
		if (errno == EAGAIN) {
			KBIT_CLR(st->base.st_flags, STF_WREADY);
		}
		if (send_bytes == 0) {
			return kgl_selector_module.sendfile(st, result, buffer, arg);
		}
		//int err = errno;
		//printf("sendfile got=[%d] file->offset=[%lld] send_bytes=[%d] length=[%d] err=[%d %s]\n",got,file->st.offset,send_bytes,bufs.iov_len,err,strerror(err));
	}
	return result(st->data, arg, (int)send_bytes);
#else
#error "no system provide sendfile"
#endif
	//printf("sendfile got=[%d] file->offset=[%lld] offset=[%lld] length=[%d]\n",got,file->offset,offset,bufs.iov_len);
}
#endif
static inline kev_result selectable_event_write(kselectable* st, result_callback result, buffer_callback buffer, void* arg) {
	if (unlikely(KBIT_TEST(st->base.st_flags, STF_WREADY2))) {
		KBIT_CLR(st->base.st_flags, STF_WREADY2);
#ifdef ENABLE_KSSL_BIO		
		if (st->ssl && buffer) {
			kssl_bio* ssl_bio = &st->ssl->bio[OP_WRITE];
			kassert(result != result_ssl_bio_write);
			kassert(arg != ssl_bio);
			kassert(BIO_pending(ssl_bio->bio) <= 0);
			return result(st->data, arg, ssl_bio->got);
		}
#endif
}
	if (unlikely(buffer == NULL)) {
		return result(st->data, arg, 0);
	}
	kassert(buffer->iov_len > 0);
	int got;

#ifdef KSOCKET_SSL
	if (selectable_is_ssl_handshake(st)) {
		kassert(st->ssl);
		got = kgl_ssl_writev(st->ssl, (kgl_iovec*)buffer->iov_base, buffer->iov_len);
	} else
#endif
		got = kgl_writev(st->fd, (kgl_iovec*)buffer->iov_base, buffer->iov_len);
	if (got >= 0) {
		return result(st->data, arg, got);
	}
#ifdef KSOCKET_SSL
	if (selectable_is_ssl_handshake(st)) {
		kassert(st->ssl);
		KBIT_CLR(st->base.st_flags, STF_WREADY);
		int err = SSL_get_error(st->ssl->ssl, got);
		if (errno == EAGAIN || err == SSL_ERROR_WANT_WRITE) {
#ifdef ENABLE_KSSL_BIO
			return selectable_ssl_write(st, result, buffer, arg);
#else
			return kgl_selector_module.write(st->base.selector, st, result, buffer, arg);
#endif
		}
	}
#endif
	if (errno == EAGAIN) {
		KBIT_CLR(st->base.st_flags, STF_WREADY);
		return kgl_selector_module.write(st->base.selector, st, result, buffer, arg);
	}
	return result(st->data, arg, got);
}
kev_result selectable_event_read(kselectable* st, result_callback result, buffer_callback buffer, void* arg) {
	assert(!KBIT_TEST(st->base.st_flags, STF_UDP));
	if (KBIT_TEST(st->base.st_flags, STF_RREADY2)) {
		KBIT_CLR(st->base.st_flags, STF_RREADY2);
#ifndef NDEBUG
#ifdef ENABLE_KSSL_BIO
		if (st->ssl && buffer) {
			kassert(st->ssl);
			kssl_bio* ssl_bio = &st->ssl->bio[OP_READ];
			int ssl_pending = SSL_pending(st->ssl->ssl);
			int bio_pending = (int)BIO_pending(ssl_bio->bio);
			kassert(st->ssl->in_early || ssl_pending > 0 || bio_pending > 0 || BIO_get_shutdown(ssl_bio->bio));
		}
#endif
#endif
	}
	if (unlikely(buffer == NULL)) {
		return result(st->data, arg, 0);
	}
	//WSABUF bufs[MAX_IOVECT_COUNT];
	//int bc = buffer(st->data, arg, bufs, MAX_IOVECT_COUNT);
	//kassert(bufs[0].iov_len > 0);
	int got;
#ifdef KSOCKET_SSL
	if (selectable_is_ssl_handshake(st)) {
		kassert(st->ssl);
		got = kgl_ssl_readv(st->ssl, (kgl_iovec*)buffer->iov_base, buffer->iov_len);
	} else
#endif
		got = kgl_readv(st->fd, (kgl_iovec*)buffer->iov_base, buffer->iov_len);

	if (got >= 0) {
		return result(st->data, arg, got);
	}
#ifdef KSOCKET_SSL
	if (selectable_is_ssl_handshake(st)) {
		kassert(st->ssl);
		KBIT_CLR(st->base.st_flags, STF_RREADY);
		int err = SSL_get_error(st->ssl->ssl, got);
		if (errno == EAGAIN || err == SSL_ERROR_WANT_READ) {
#ifdef ENABLE_KSSL_BIO
			return selectable_ssl_read(st, result, buffer, arg);
#else
			return kgl_selector_module.read(st->base.selector, st, result, buffer, arg);
#endif
		}
		return result(st->data, arg, got);
	}
#endif
	if (errno == EAGAIN) {
		kassert(!KBIT_TEST(st->base.st_flags, STF_RREADY2));
		KBIT_CLR(st->base.st_flags, STF_RREADY);
		return kgl_selector_module.read(st->base.selector, st, result, buffer, arg);
	}
	return result(st->data, arg, got);
}
kev_result selectable_read_event(kselectable* st)
{
#ifdef STF_ET
	/* epoll notice fd read event use LT model other use ET model */
	if (KBIT_TEST(st->base.st_flags, STF_ET))
#endif
		KBIT_CLR(st->base.st_flags, STF_READ);
	if (unlikely(KBIT_TEST(st->base.st_flags, STF_UDP))) {
		return selectable_udp_read_event(st, st->e[OP_READ].result, st->e[OP_READ].buffer, st->e[OP_READ].arg);
	}
#ifdef ENABLE_KSSL_BIO
	if (!KBIT_TEST(st->base.st_flags, STF_RREADY2)) {
		return selectable_low_event_read(st, st->e[OP_READ].result, st->e[OP_READ].buffer, st->e[OP_READ].arg);
	}
#endif
	return selectable_event_read(st, st->e[OP_READ].result, st->e[OP_READ].buffer, st->e[OP_READ].arg);
}
kev_result selectable_write_event(kselectable* st)
{
	assert(!KBIT_TEST(st->base.st_flags, STF_UDP));
#ifndef _WIN32
	if (KBIT_TEST(st->base.st_flags,STF_SENDFILE)) {
		KBIT_CLR(st->base.st_flags,STF_WRITE|STF_RDHUP|STF_SENDFILE);
		return selectable_event_sendfile(st, st->e[OP_WRITE].result, st->e[OP_WRITE].buffer, st->e[OP_WRITE].arg);
	}
#endif
	KBIT_CLR(st->base.st_flags, STF_WRITE | STF_RDHUP);
	if (KBIT_TEST(st->base.st_flags, STF_ERR) > 0) {
		return st->e[OP_WRITE].result(st->data, st->e[OP_WRITE].arg, -1);
	}
#ifdef ENABLE_KSSL_BIO
	if (!KBIT_TEST(st->base.st_flags, STF_WREADY2)) {
		return selectable_low_event_write(st, st->e[OP_WRITE].result, st->e[OP_WRITE].buffer, st->e[OP_WRITE].arg);
	}
#endif
	return selectable_event_write(st, st->e[OP_WRITE].result, st->e[OP_WRITE].buffer, st->e[OP_WRITE].arg);
}
void selectable_next_read(kselectable* st, result_callback result, void* arg)
{
	kassert(KBIT_TEST(st->base.st_flags, STF_READ | STF_RREADY2) == 0);
	kassert(kselector_is_same_thread(st->base.selector));
	st->e[OP_READ].arg = arg;
	st->e[OP_READ].result = result;
	st->e[OP_READ].buffer = NULL;
	KBIT_SET(st->base.st_flags, STF_READ | STF_RREADY2);
	KBIT_CLR(st->base.st_flags, STF_RDHUP);
	kselector_add_list(st->base.selector, st, KGL_LIST_READY);
}
void selectable_next_write(kselectable* st, result_callback result, void* arg)
{
	kassert(KBIT_TEST(st->base.st_flags, STF_WRITE | STF_WREADY2) == 0);
	kassert(kselector_is_same_thread(st->base.selector));
	st->e[OP_WRITE].arg = arg;
	st->e[OP_WRITE].result = result;
	st->e[OP_WRITE].buffer = NULL;
	KBIT_SET(st->base.st_flags, STF_WRITE | STF_WREADY2);
	KBIT_CLR(st->base.st_flags, STF_RDHUP);
	kselector_add_list(st->base.selector, st, KGL_LIST_READY);
}
kev_result selectable_read(kselectable* st, result_callback result, kgl_iovec* buffer, void* arg)
{
#ifdef KSOCKET_SSL
	if (selectable_is_ssl_handshake(st)) {
		if (
#ifdef SSL_READ_EARLY_DATA_SUCCESS
			st->ssl->in_early ||
#endif
			SSL_pending(st->ssl->ssl) > 0) {
			//printf("st=[%p] ssl_pending=[%d]\n",st, pending_read);
#ifdef ENABLE_KSSL_BIO
			kassert(result != result_ssl_bio_read);
#endif
			kassert(!KBIT_TEST(st->base.st_flags, STF_READ));
			//ssl still have data to read
			st->e[OP_READ].arg = arg;
			st->e[OP_READ].result = result;
			st->e[OP_READ].buffer = buffer;
			KBIT_SET(st->base.st_flags, STF_READ | STF_RREADY2);
			KBIT_CLR(st->base.st_flags, STF_RDHUP);
			return kselectable_is_read_ready(st->base.selector, st);
		}
#ifdef ENABLE_KSSL_BIO
		return selectable_ssl_read(st, result, buffer, arg);
#endif
	}
#endif
	return kgl_selector_module.read(st->base.selector, st, result, buffer, arg);
}
kev_result selectable_write(kselectable* st, result_callback result, kgl_iovec *buffer, void* arg)
{
	kassert(KBIT_TEST(st->base.st_flags, STF_WRITE | STF_WREADY2) == 0);
#ifdef ENABLE_KSSL_BIO
	if (selectable_is_ssl_handshake(st)) {
		kassert(st->ssl);
		return selectable_ssl_write(st, result, buffer, arg);
	}
#endif
	return kgl_selector_module.write(st->base.selector, st, result, buffer, arg);
}

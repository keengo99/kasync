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
static int kgl_ssl_writev(kssl_session* ssl, WSABUF* buffer, int bc)
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
			if (this_len <= 0) {
				return (got > 0 ? got : this_len);
			}
			got += this_len;
			len -= this_len;
			hot += this_len;
		}
	}
	return got;
}
static int kgl_ssl_readv(kssl_session* ssl, WSABUF* buffer, int bc)
{
	int got = 0;
	int i = 0;
	int this_len;
	for (; i < bc; i++) {
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
				this_len = (int)read_bytes;
				got += this_len;
				len -= this_len;
				hot += this_len;
				continue;
			}
#endif
			this_len = SSL_read(ssl->ssl, hot, len);
			if (this_len <= 0) {
				return (got > 0 ? got : this_len);
			}
			got += this_len;
			len -= this_len;
			hot += this_len;
		}
	}
	return got;
}
#endif
static int kgl_writev(SOCKET s, WSABUF* buffer, int bc)
{
#ifdef HAVE_WRITEV
	return writev(s, buffer, bc);
#else
	int got = 0;
	for (int i = 0; i < bc; i++) {
		char* hot = (char*)buffer[i].iov_base;
		int len = buffer[i].iov_len;
		while (len > 0) {
			int this_len = send(s, hot, len, 0);
			if (this_len <= 0) {
				return (got > 0 ? got : this_len);
			}
			got += this_len;
			len -= this_len;
			hot += this_len;
		}
	}
	return got;
#endif
}
static int kgl_readv(SOCKET s, WSABUF* buffer, int bc)
{
#ifdef HAVE_READV
	return readv(s, buffer, bc);
#else
	int got = 0;
	for (int i = 0; i < bc; i++) {
		char* hot = (char*)buffer[i].iov_base;
		int len = buffer[i].iov_len;
		while (len > 0) {
			int this_len = recv(s, hot, len, 0);
			if (this_len <= 0) {
				return (got > 0 ? got : this_len);
			}
			got += this_len;
			len -= this_len;
			hot += this_len;
		}
	}
	return got;
#endif
}
void selectable_clean(kselectable* st)
{
	/* aio file type do not call selectable_clean */
	kassert(KBIT_TEST(st->base.st_flags, STF_LOCK|STF_AIO_FILE) == 0);
	kassert(st->base.queue.next == NULL);
	kassert(st->base.queue.prev == NULL);
	if (ksocket_opened(st->fd)) {
		if (st->base.selector) {
			kgl_selector_module.remove(st->base.selector, st);
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
bool selectable_remove(kselectable* st)
{
	kgl_selector_module.remove(st->base.selector, st);
	return true;
}
void selectable_shutdown(kselectable* st)
{
#ifdef _WIN32
	ksocket_cancel(st->fd);
#endif
	ksocket_shutdown(st->fd, SHUT_RDWR);
}
#ifndef _WIN32
int selectable_recvmsg(kselectable* st)
{
	kconnection* c = kgl_list_data(st, kconnection, st);
	WSABUF bufs[16];
	WSABUF addr;
	int bc = st->e[OP_READ].buffer(st->data, st->e[OP_READ].arg, bufs, 16);
	kconnection_buffer_addr(st->data, st, &addr, 1);
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (struct sockaddr*)addr.iov_base;
	msg.msg_namelen = addr.iov_len;
	msg.msg_iov = bufs;
	msg.msg_iovlen = bc;
	msg.msg_control = c->udp->pktinfo;
	if (c->udp) {
		memset(c->udp, 0, sizeof(kudp_extend));
		msg.msg_controllen = sizeof(c->udp->pktinfo);
	}
	return recvmsg(st->fd, &msg, 0);
}
#endif
void selectable_udp_read_event(kselectable* st)
{
#ifndef _WIN32
	assert(KBIT_TEST(st->base.st_flags, STF_UDP));
#ifdef STF_ET
	if (KBIT_TEST(st->base.st_flags, STF_ET))
#endif
		KBIT_CLR(st->base.st_flags, STF_READ);
	int got = selectable_recvmsg(st);
	if (got>=0) {
		st->e[OP_READ].result(st->data, st->e[OP_READ].arg, got);
		return;
	}
	switch(errno) {
	case EAGAIN:
	case EINTR:
		KBIT_CLR(st->base.st_flags, STF_RREADY);
		if (kgl_selector_module.read(st->base.selector, st, st->e[OP_READ].result, st->e[OP_READ].buffer, st->e[OP_READ].arg)) {
			return;
		}
		break;
	case ENOMEM:
		st->e[OP_READ].result(st->data, st->e[OP_READ].arg, ST_ERR_NOMEM);
		break;
	default:
		st->e[OP_READ].result(st->data, st->e[OP_READ].arg, ST_ERR_RESULT);
		break;
	}
#else
	//windows iocp never goto here.
	assert(false);
#endif
}
void selectable_read_event(kselectable* st)
{
#ifdef STF_ET
	if (KBIT_TEST(st->base.st_flags, STF_ET))
#endif
		KBIT_CLR(st->base.st_flags, STF_READ);
	selectable_event_read(st, st->e[OP_READ].result, st->e[OP_READ].buffer, st->e[OP_READ].arg);
}
void selectable_write_event(kselectable* st)
{
#ifndef _WIN32
	if (KBIT_TEST(st->base.st_flags,STF_SENDFILE)) {
		KBIT_CLR(st->base.st_flags,STF_WRITE|STF_RDHUP|STF_SENDFILE);
		selectable_event_sendfile(st, st->e[OP_WRITE].result, st->e[OP_WRITE].buffer, st->e[OP_WRITE].arg);
		return;
	}
#endif
	KBIT_CLR(st->base.st_flags, STF_WRITE | STF_RDHUP);
	if (KBIT_TEST(st->base.st_flags, STF_ERR) > 0) {
		st->e[OP_WRITE].result(st->data, st->e[OP_WRITE].arg, -1);
		return;
	}
	selectable_event_write(st, st->e[OP_WRITE].result, st->e[OP_WRITE].buffer, st->e[OP_WRITE].arg);
}
#ifdef ENABLE_KSSL_BIO
static bool selectable_ssl_read(kselectable* st, result_callback result, buffer_callback buffer, void* arg)
{
	kssl_bio* ssl_bio = &st->ssl->bio[OP_READ];
	ssl_bio->buffer = buffer;
	ssl_bio->result = result;
	ssl_bio->arg = arg;
	ssl_bio->st = st;
	kassert(result != result_ssl_bio_read);
	kassert(buffer != buffer_ssl_bio_read);
	kassert(arg != ssl_bio);
	if (BIO_pending(ssl_bio->bio) > 0) {
		kassert(!KBIT_TEST(st->base.st_flags, STF_READ));
		//ssl still have data to read
		st->e[OP_READ].arg = arg;
		st->e[OP_READ].result = result;
		st->e[OP_READ].buffer = buffer;
		KBIT_SET(st->base.st_flags, STF_READ | STF_RREADY2);
		KBIT_CLR(st->base.st_flags, STF_RDHUP);
		kselector_add_list(st->base.selector, st, KGL_LIST_READY);
		//selectable_event_read(st,result,buffer,arg);
		return true;
	}
	return kgl_selector_module.read(st->base.selector, st, result_ssl_bio_read, buffer_ssl_bio_read, ssl_bio);
}
static bool selectable_ssl_write(kselectable* st, result_callback result, buffer_callback buffer, void* arg)
{
	kssl_bio* ssl_bio = &st->ssl->bio[OP_WRITE];
	ssl_bio->got = 0;
	if (buffer) {
		WSABUF bufs[MAX_IOVECT_COUNT];
		ssl_bio->got = kgl_ssl_writev(st->ssl, bufs, buffer(st->data, arg, bufs, MAX_IOVECT_COUNT));
	}
	if (BIO_pending(ssl_bio->bio) <= 0) {
		st->e[OP_WRITE].arg = arg;
		st->e[OP_WRITE].result = result;
		st->e[OP_WRITE].buffer = buffer;
		KBIT_SET(st->base.st_flags, STF_WRITE | STF_WREADY2);
		kselector_add_list(st->base.selector, st, KGL_LIST_READY);
		return true;
	}
	ssl_bio->buffer = buffer;
	ssl_bio->result = result;
	ssl_bio->arg = arg;
	ssl_bio->st = st;
	return kgl_selector_module.write(st->base.selector, st, result_ssl_bio_write, buffer_ssl_bio_write, ssl_bio);
}

inline kev_result selectable_low_event_write(kselectable* st, result_callback result, buffer_callback buffer, void* arg)
{
#ifdef _WIN32
	kassert(false);
#endif
	if (unlikely(buffer == NULL)) {
		return result(st->data, arg, 0);
	}
	WSABUF bufs[MAX_IOVECT_COUNT];
	int bc = buffer(st->data, arg, bufs, MAX_IOVECT_COUNT);
	kassert(bufs[0].iov_len > 0);
	int got = kgl_writev(st->fd, bufs, bc);
	if (got >= 0) {
		return result(st->data, arg, got);
	}
	if (errno == EAGAIN) {
		KBIT_CLR(st->base.st_flags, STF_WREADY);
		if (kgl_selector_module.write(st->base.selector, st, result, buffer, arg)) {
			return kev_ok;
		}
	}
	return result(st->data, arg, got);
}
inline kev_result selectable_low_event_read(kselectable* st, result_callback result, buffer_callback buffer, void* arg)
{
#ifdef _WIN32
	kassert(false);
#endif
	if (unlikely(buffer == NULL)) {
		return result(st->data, arg, 0);
	}
	WSABUF bufs[MAX_IOVECT_COUNT];
	int bc = buffer(st->data, arg, bufs, MAX_IOVECT_COUNT);
	kassert(bufs[0].iov_len > 0);
	int got = kgl_readv(st->fd, bufs, bc);
	if (got >= 0) {
		return result(st->data, arg, got);
	}
	if (errno == EAGAIN) {
		KBIT_CLR(st->base.st_flags, STF_RREADY);
		if (kgl_selector_module.read(st->base.selector, st, result, buffer, arg)) {
			return kev_ok;
		}
	}
	return result(st->data, arg, got);
}
#endif
bool selectable_try_write(kselectable* st, result_callback result, buffer_callback buffer, void* arg)
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
kev_result selectable_read(kselectable* st, result_callback result, buffer_callback buffer, void* arg)
{
	if (!selectable_try_read(st, result, buffer, arg)) {
		return result(st->data, arg, -1);
	}
	return kev_ok;
}
kev_result selectable_write(kselectable* st, result_callback result, buffer_callback buffer, void* arg)
{
	if (!selectable_try_write(st, result, buffer, arg)) {
		return result(st->data, arg, -1);
	}
	return kev_ok;
}

bool selectable_try_read(kselectable* st, result_callback result, buffer_callback buffer, void* arg)
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
			kselector_add_list(st->base.selector, st, KGL_LIST_READY);
			//selectable_event_read(st,result, buffer,arg);
			return true;
		}
#ifdef ENABLE_KSSL_BIO
		return selectable_ssl_read(st, result, buffer, arg);
#endif
	}
#endif
	return kgl_selector_module.read(st->base.selector, st, result, buffer, arg);
}
#ifndef _WIN32
kev_result selectable_event_sendfile(kselectable *st,result_callback result, buffer_callback buffer, void* arg) {
	WSABUF bufs;
	buffer(st->data,arg,&bufs,1);
	kasync_file *file = (kasync_file *)bufs.iov_base;
	off_t offset = file->st.offset;
	assert(sizeof(off_t)==sizeof(int64_t));
	int got = -1;
#ifdef KSOCKET_SSL
#ifdef LINUX_IOURING
	//linux iouring sendfile without ssl do not goto here.
	assert(st->ssl);
#endif
	if (st->ssl) {
		assert(kgl_ssl_support_sendfile(st->ssl));
#if defined(BIO_get_ktls_send)
		got = SSL_sendfile(st->ssl->ssl,file->st.fd,offset,bufs.iov_len,0);
		if (got>=0) {
			return result(st->data, arg, got);
		}
		int err = SSL_get_error(st->ssl->ssl, got);
		if (err==SSL_ERROR_WANT_WRITE) {	
			KBIT_CLR(st->base.st_flags, STF_WREADY);
			if (kgl_selector_module.sendfile(st, result, buffer, arg)) {
				return kev_ok;
			}
		}
#endif
		return result(st->data, arg, got);
	}
#endif

#ifdef LINUX
	got = sendfile(st->fd,file->st.fd, &offset, bufs.iov_len);
	if (got >= 0) {
		return result(st->data, arg, got);
	}
	if (errno == EAGAIN) {
		KBIT_CLR(st->base.st_flags, STF_WREADY);
		if (kgl_selector_module.sendfile(st, result, buffer, arg)) {
			return kev_ok;
		}
	}
	return result(st->data, arg, got);
#elif BSD_OS
#ifdef DARWIN
	off_t send_bytes = bufs.iov_len;
	got = sendfile(file->st.fd, st->fd, offset, &send_bytes,NULL,0);
#else
	off_t send_bytes = 0;
	got = sendfile(file->st.fd, st->fd, offset, bufs.iov_len, NULL, &send_bytes,0);
#endif
	if (got<0) {
		if (errno==EAGAIN) {
			KBIT_CLR(st->base.st_flags, STF_WREADY);
		}
		if (send_bytes==0) {
			if (kgl_selector_module.sendfile(st, result, buffer, arg)) {
				return kev_ok;
			}
		}
		//int err = errno;
		//printf("sendfile got=[%d] file->offset=[%lld] send_bytes=[%d] length=[%d] err=[%d %s]\n",got,file->st.offset,send_bytes,bufs.iov_len,err,strerror(err));
	}
	return result(st->data,arg,(int)send_bytes);
#else
#error "no system provide sendfile" 
#endif
	//printf("sendfile got=[%d] file->offset=[%lld] offset=[%lld] length=[%d]\n",got,file->offset,offset,bufs.iov_len);	
}
#endif
kev_result selectable_event_write(kselectable* st, result_callback result, buffer_callback buffer, void* arg)
{
	WSABUF bufs[MAX_IOVECT_COUNT];
	if (unlikely(KBIT_TEST(st->base.st_flags, STF_WREADY2))) {
		KBIT_CLR(st->base.st_flags, STF_WREADY2);
#ifdef ENABLE_KSSL_BIO		
		if (st->ssl && buffer) {
			kssl_bio* ssl_bio = &st->ssl->bio[OP_WRITE];
			kassert(buffer != buffer_ssl_bio_write);
			kassert(result != result_ssl_bio_write);
			kassert(arg != ssl_bio);
			kassert(BIO_pending(ssl_bio->bio) <= 0);
			return result(st->data, arg, ssl_bio->got);
		}
#endif
#ifdef ENABLE_KSSL_BIO
	} else {
		return selectable_low_event_write(st, st->e[OP_WRITE].result, st->e[OP_WRITE].buffer, st->e[OP_WRITE].arg);
#endif
	}
	if (unlikely(buffer == NULL)) {
		return result(st->data, arg, 0);
	}
	int bc = buffer(st->data, arg, bufs, MAX_IOVECT_COUNT);
	kassert(bufs[0].iov_len > 0);
	int got;

#ifdef KSOCKET_SSL
	if (selectable_is_ssl_handshake(st)) {
		kassert(st->ssl);
		got = kgl_ssl_writev(st->ssl, bufs, bc);
	} else
#endif
		got = kgl_writev(st->fd, bufs, bc);
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
			if (!selectable_ssl_write(st, result, buffer, arg)) {
				return result(st->data, arg, got);
			}
			return kev_ok;
#endif
			if (!kgl_selector_module.write(st->base.selector, st, result, buffer, arg)) {
				return result(st->data, arg, got);
			}
			return kev_ok;
		}
	}
#endif
	if (errno == EAGAIN) {
		KBIT_CLR(st->base.st_flags, STF_WREADY);
		if (kgl_selector_module.write(st->base.selector, st, result, buffer, arg)) {
			return kev_ok;
		}
	}
	return result(st->data, arg, got);
}
kev_result selectable_event_read(kselectable* st, result_callback result, buffer_callback buffer, void* arg)
{
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
#ifdef ENABLE_KSSL_BIO
	} else {
		return selectable_low_event_read(st, st->e[OP_READ].result, st->e[OP_READ].buffer, st->e[OP_READ].arg);
	}
#endif
	}
	if (unlikely(buffer == NULL)) {
		return result(st->data, arg, 0);
	}
	WSABUF bufs[MAX_IOVECT_COUNT];
	int bc = buffer(st->data, arg, bufs, MAX_IOVECT_COUNT);
	kassert(bufs[0].iov_len > 0);
	int got;
#ifdef KSOCKET_SSL
	if (selectable_is_ssl_handshake(st)) {
		kassert(st->ssl);
		got = kgl_ssl_readv(st->ssl, bufs, bc);
	} else
#endif
		got = kgl_readv(st->fd, bufs, bc);

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
			if (!selectable_ssl_read(st, result, buffer, arg)) {
				return result(st->data, arg, got);
			}
			return kev_ok;
#endif
			if (kgl_selector_module.read(st->base.selector, st, result, buffer, arg)) {
				return kev_ok;
			}
		}
		return result(st->data, arg, got);
	}
#endif
	if (errno == EAGAIN) {
		kassert(!KBIT_TEST(st->base.st_flags, STF_RREADY2));
		KBIT_CLR(st->base.st_flags, STF_RREADY);
		if (kgl_selector_module.read(st->base.selector, st, result, buffer, arg)) {
			return kev_ok;
		}
	}
	return result(st->data, arg, got);
}
bool selectable_readhup(kselectable* st, result_callback result, void* arg)
{
	if (kgl_selector_module.readhup) {
		return kgl_selector_module.readhup(st->base.selector, st, result, arg);
	}
	return false;
}
void selectable_remove_readhup(kselectable* st)
{
	if (kgl_selector_module.remove_readhup) {
		kgl_selector_module.remove_readhup(st->base.selector, st);
	}
}

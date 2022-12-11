#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include "kfeature.h"
#include "kselectable.h"
#include "ksocket.h"
#include "kmalloc.h"
#include "kfiber.h"
#include "klist.h"
#include "kudp.h"

#define MAXSENDBUF 16
#ifdef KSOCKET_SSL
static int kgl_ssl_writev(kssl_session *ssl, LPWSABUF buffer, int bc)
{
	int got = 0;
	for (int i = 0; i < bc; i++) {
		char *hot = (char *)buffer[i].iov_base;
		int len = buffer[i].iov_len;
		while (len > 0) {
#ifdef ENABLE_KSSL_BIO
			//ssl bio max write 64KB
			int left = 65536 - got;
			if (left <= 0) {
				return got;
			}
			len = MIN(left, len);
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
static int kgl_ssl_readv(kssl_session *ssl, LPWSABUF buffer, int bc)
{
	int got = 0;
	int i = 0;
	int this_len;
	for (;i < bc; i++) {
		u_char *hot = (u_char *)buffer[i].iov_base;
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
static int kgl_writev(SOCKET s,LPWSABUF buffer,int bc)
{
#ifdef HAVE_WRITEV
	return writev(s,buffer,bc);
#else
	int got = 0;
	for (int i=0;i<bc;i++) {
		char *hot = (char *)buffer[i].iov_base;
		int len = buffer[i].iov_len;
		while (len>0) {
			int this_len = send(s,hot,len,0);
			if (this_len<=0) {
				return (got>0?got:this_len);
			}
			got += this_len;
			len -= this_len;
			hot += this_len;
		}
	}
	return got;
#endif
}
static int kgl_readv(SOCKET s,LPWSABUF buffer,int bc)
{
#ifdef HAVE_READV
	return readv(s,buffer,bc);
#else
	int got = 0;
	for (int i=0;i<bc;i++) {
		char *hot = (char *)buffer[i].iov_base;
		int len = buffer[i].iov_len;
		while (len>0) {
			int this_len = recv(s,hot,len,0);
			if (this_len<=0) {
				return (got>0?got:this_len);
			}
			got += this_len;
			len -= this_len;
			hot += this_len;
		}
	}
	return got;
#endif
}
void selectable_bind_opaque(kselectable *st, KOPAQUE data, kgl_opaque_type type)
{
	st->data = data;
	switch (type) {
	case kgl_opaque_server:
		KBIT_SET(st->st_flags, STF_OPAQUE_SERVER);
		break;
	case kgl_opaque_server_http2:
		KBIT_SET(st->st_flags, STF_OPAQUE_SERVER | STF_OPAQUE_HTTP2);
		break;
	case kgl_opaque_client_http2:
		KBIT_SET(st->st_flags, STF_OPAQUE_HTTP2);
		break;
	default:
		break;
	}
}
void selectable_clean(kselectable *st)
{
	kassert(KBIT_TEST(st->st_flags, STF_LOCK) == 0);
	kassert(st->queue.next == NULL);
	kassert(st->queue.prev == NULL);
	if (ksocket_opened(st->fd)) {
		if (st->selector) {
			kgl_selector_module.remove(st->selector, st);
		}
		ksocket_shutdown(st->fd, SHUT_RDWR);
		ksocket_close(st->fd);
	}
#ifdef KSOCKET_SSL
	if (st->ssl) {
		SSL_free(st->ssl->ssl);
		xfree(st->ssl);
	}
#endif
}
bool selectable_remove(kselectable *st)
{
	kgl_selector_module.remove(st->selector, st);
	return true;
}
void selectable_shutdown(kselectable *st)
{
#if 0
	if (KBIT_TEST(st->st_flags, STF_RECVFROM)) {
		ksocket_close(st->fd);
		ksocket_init(st->fd);
		return;
	}
#endif
#ifdef _WIN32
	ksocket_cancel(st->fd);
#endif
	ksocket_shutdown(st->fd, SHUT_RDWR);
}
void selectable_udp_write_event(kselectable* st)
{
	assert(KBIT_TEST(st->st_flags, STF_UDP));
#ifdef STF_ET
	if (KBIT_TEST(st->st_flags, STF_ET))
#endif
		KBIT_CLR(st->st_flags, STF_READ);
#ifndef _WIN32
	kconnection* c = kgl_list_data(st, kconnection, st);
	if (unlikely(st->e[OP_WRITE].buffer == NULL)) {
		return result(st->data, arg, 0);
	}
	int got = sendmsg(st->fd, (struct msghdr *)st->e[OP_WRITE].buffer_ctx, 0);
	if (got == -1 && errno == EAGAIN) {
		KBIT_CLR(st->st_flags, STF_WREADY);
		if (kgl_selector_module.sendto(st->selector, st, st->e[OP_WRITE].result, st->e[OP_WRITE].buffer_ctx, st->e[OP_WRITE].arg)) {
			return;
		}
	}
#else
	//windows never go here
	assert(false);
	int got = -1;
#endif
	st->e[OP_WRITE].result(st->data, st->e[OP_WRITE].arg, got);
}
void selectable_udp_read_event(kselectable *st)
{
	assert(KBIT_TEST(st->st_flags,STF_UDP));
#ifdef STF_ET
	if (KBIT_TEST(st->st_flags, STF_ET))
#endif
		KBIT_CLR(st->st_flags,STF_READ);
#ifndef _WIN32
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
	int got = recvmsg(st->fd,&msg,0);
#if 0
	WSABUF buf;
	WSABUF addr;
	int bc = st->e[OP_READ].buffer(st->data, st->e[OP_READ].arg, &buf, 1);
	kassert(bc == 1);
	bc = kconnection_buffer_addr(st->data, st, &addr, 1);
	kassert(bc == 1);
	socklen_t addr_len = (socklen_t)addr.iov_len;
	int got = recvfrom(st->fd, (char *)buf.iov_base, buf.iov_len, 0, (struct sockaddr *)addr.iov_base, &addr_len);
#endif
	if (got==-1 && errno==EAGAIN) {
		KBIT_CLR(st->st_flags,STF_RREADY);
		if (kgl_selector_module.recvfrom(st->selector, st, st->e[OP_READ].result, st->e[OP_READ].buffer, st->e[OP_READ].arg)) {
			return;
		}
	}
#else
	//windows never go here
	assert(false);
	int got = -1;
#endif
	st->e[OP_READ].result(st->data, st->e[OP_READ].arg, got);
}
void selectable_read_event(kselectable *st)
{
#ifdef STF_ET
      if (KBIT_TEST(st->st_flags, STF_ET))
#endif
        KBIT_CLR(st->st_flags, STF_READ);	
#ifdef ENABLE_KSSL_BIO
	if (!KBIT_TEST(st->st_flags, STF_RREADY2)) {
		selectable_low_event_read(st, st->e[OP_READ].result, st->e[OP_READ].buffer, st->e[OP_READ].arg);
		return;
	}
#endif
	selectable_event_read(st, st->e[OP_READ].result, st->e[OP_READ].buffer, st->e[OP_READ].arg);
}
void selectable_write_event(kselectable *st)
{
	KBIT_CLR(st->st_flags, STF_WRITE|STF_RDHUP);
	if (KBIT_TEST(st->st_flags, STF_ERR) > 0) {
		st->e[OP_WRITE].result(st->data, st->e[OP_WRITE].arg, -1);
		return;
	}
#ifdef ENABLE_KSSL_BIO
	if (!KBIT_TEST(st->st_flags, STF_WREADY2)) {
		selectable_low_event_write(st, st->e[OP_WRITE].result, st->e[OP_WRITE].buffer, st->e[OP_WRITE].arg);
		return;
	}
#endif
	selectable_event_write(st, st->e[OP_WRITE].result, st->e[OP_WRITE].buffer, st->e[OP_WRITE].arg);
}
#ifdef ENABLE_KSSL_BIO
static bool selectable_ssl_read(kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	kssl_bio *ssl_bio = &st->ssl->bio[OP_READ];
	ssl_bio->buffer = buffer;
	ssl_bio->result = result;
	ssl_bio->arg = arg;
	ssl_bio->st = st;
	kassert(result != result_ssl_bio_read);
	kassert(buffer != buffer_ssl_bio_read);
	kassert(arg != ssl_bio);
	if (BIO_pending(ssl_bio->bio) > 0) {
		kassert(!KBIT_TEST(st->st_flags, STF_READ));
		//ssl still have data to read
		st->e[OP_READ].arg = arg;
		st->e[OP_READ].result = result;
		st->e[OP_READ].buffer = buffer;
		KBIT_SET(st->st_flags, STF_READ | STF_RREADY2);
		KBIT_CLR(st->st_flags, STF_RDHUP);
		kselector_add_list(st->selector, st, KGL_LIST_READY);
		//selectable_event_read(st,result,buffer,arg);
		return true;
	}
	return kgl_selector_module.read(st->selector, st, result_ssl_bio_read, buffer_ssl_bio_read, ssl_bio);
}
static bool selectable_ssl_write(kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	kssl_bio *ssl_bio = &st->ssl->bio[OP_WRITE];
	ssl_bio->got = 0;
	if (buffer) {
		WSABUF recvBuf[MAXSENDBUF];
		int bufferCount = buffer(st->data,arg, recvBuf, MAXSENDBUF);
		ssl_bio->got = kgl_ssl_writev(st->ssl, recvBuf, bufferCount);
	}
	if (BIO_pending(ssl_bio->bio) <= 0) {
		st->e[OP_WRITE].arg = arg;
		st->e[OP_WRITE].result = result;
		st->e[OP_WRITE].buffer = buffer;
		KBIT_SET(st->st_flags, STF_WRITE | STF_WREADY2);
		kselector_add_list(st->selector, st, KGL_LIST_READY);
		return true;
	}
	ssl_bio->buffer = buffer;
	ssl_bio->result = result;
	ssl_bio->arg = arg;
	ssl_bio->st = st;
	return kgl_selector_module.write(st->selector, st, result_ssl_bio_write, buffer_ssl_bio_write, ssl_bio);
}

void selectable_low_event_write(kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
#ifdef _WIN32
	kassert(false);
#endif
	if (unlikely(buffer == NULL)) {
		result(st->data,arg, 0);
		return;
	}
	WSABUF recvBuf[MAXSENDBUF];
	int bc = buffer(st->data,arg, recvBuf, MAXSENDBUF);
	kassert(recvBuf[0].iov_len > 0);
	int got = kgl_writev(st->fd, recvBuf, bc);
	if (got >= 0) {
		result(st->data,arg, got);
		return;
	}
	if (errno == EAGAIN) {
		KBIT_CLR(st->st_flags, STF_WREADY);
		if (kgl_selector_module.write(st->selector, st, result, buffer, arg)) {
			return;
		}
	}
	result(st->data,arg, got);
}
void selectable_low_event_read(kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
#ifdef _WIN32
	kassert(false);
#endif
	if (unlikely(buffer == NULL)) {
		result(st->data,arg, 0);
		return;
	}
	WSABUF recvBuf[MAXSENDBUF];
	int bc = buffer(st->data,arg, recvBuf, MAXSENDBUF);
	kassert(recvBuf[0].iov_len > 0);
	int got = kgl_readv(st->fd, recvBuf, bc);
	if (got >= 0) {
		result(st->data,arg, got);
		return;
	}
	if (errno == EAGAIN) {
		KBIT_CLR(st->st_flags, STF_RREADY);
		if (kgl_selector_module.read(st->selector, st, result, buffer, arg)) {
			return;
		}
	}
	result(st->data,arg, got);
}
#endif
bool selectable_try_write(kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	kassert(kfiber_check_result_callback(result));
	kassert(KBIT_TEST(st->st_flags, STF_WRITE|STF_WREADY2) == 0);
#ifdef ENABLE_KSSL_BIO
	if (selectable_is_ssl_handshake(st)) {
		kassert(st->ssl);
		return selectable_ssl_write(st, result, buffer,arg);
	}
#endif
	return kgl_selector_module.write(st->selector, st, result, buffer, arg);
}
void selectable_next_read(kselectable *st, result_callback result, void *arg)
{
	kassert(KBIT_TEST(st->st_flags, STF_READ|STF_RREADY2) == 0);
	kassert(kselector_is_same_thread(st->selector));
	st->e[OP_READ].arg = arg;
	st->e[OP_READ].result = result;
	st->e[OP_READ].buffer = NULL;
	KBIT_SET(st->st_flags, STF_READ|STF_RREADY2);
	KBIT_CLR(st->st_flags, STF_RDHUP);
	kselector_add_list(st->selector, st, KGL_LIST_READY);
}
void selectable_next_write(kselectable *st, result_callback result, void *arg)
{
	kassert(KBIT_TEST(st->st_flags, STF_WRITE|STF_WREADY2) == 0);
	kassert(kselector_is_same_thread(st->selector));
	st->e[OP_WRITE].arg = arg;
	st->e[OP_WRITE].result = result;
	st->e[OP_WRITE].buffer = NULL;
	KBIT_SET(st->st_flags, STF_WRITE | STF_WREADY2);
	KBIT_CLR(st->st_flags, STF_RDHUP);
	kselector_add_list(st->selector, st, KGL_LIST_READY);	
}
kev_result selectable_read(kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	if (!selectable_try_read(st, result, buffer, arg)) {
		return result(st->data, arg, -1);
	}
	return kev_ok;
}
kev_result selectable_write(kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	if (!selectable_try_write(st, result, buffer, arg)) {
		return result(st->data, arg, -1);
	}
	return kev_ok;
}

bool selectable_try_read(kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	kassert(kfiber_check_result_callback(result));
#ifdef KSOCKET_SSL
	if (selectable_is_ssl_handshake(st)) {
		if (
#ifdef SSL_READ_EARLY_DATA_SUCCESS
			st->ssl->in_early || 
#endif
			SSL_pending(st->ssl->ssl)>0) {
			//printf("st=[%p] ssl_pending=[%d]\n",st, pending_read);
#ifdef ENABLE_KSSL_BIO
			kassert(result != result_ssl_bio_read);
#endif
			kassert(!KBIT_TEST(st->st_flags, STF_READ));
			//ssl still have data to read
			st->e[OP_READ].arg = arg;
			st->e[OP_READ].result = result;
			st->e[OP_READ].buffer = buffer;
			KBIT_SET(st->st_flags, STF_READ|STF_RREADY2);
			KBIT_CLR(st->st_flags, STF_RDHUP);
			kselector_add_list(st->selector, st, KGL_LIST_READY);
			//selectable_event_read(st,result, buffer,arg);
			return true;
		}
#ifdef ENABLE_KSSL_BIO
		return selectable_ssl_read(st,result, buffer,arg);
#endif
	}
#endif
	return kgl_selector_module.read(st->selector, st, result, buffer, arg);
}

kev_result selectable_event_write(kselectable *st,result_callback result, buffer_callback buffer, void *arg)
{
	WSABUF recvBuf[MAXSENDBUF];
	if (KBIT_TEST(st->st_flags, STF_WREADY2)) {
		KBIT_CLR(st->st_flags, STF_WREADY2);
#ifdef ENABLE_KSSL_BIO		
		if (st->ssl && buffer) {
			kssl_bio *ssl_bio = &st->ssl->bio[OP_WRITE];			
			kassert(buffer != buffer_ssl_bio_write);
			kassert(result != result_ssl_bio_write);
			kassert(arg != ssl_bio);
			kassert(BIO_pending(ssl_bio->bio) <= 0);
			return result(st->data,arg, ssl_bio->got);
		}
#endif
	}
	if (unlikely(buffer==NULL)) {
		return result(st->data,arg,0);
	}
	int bc = buffer(st->data,arg,recvBuf, MAXSENDBUF);
	kassert(recvBuf[0].iov_len>0);
	int got;
#ifdef KSOCKET_SSL
	if (selectable_is_ssl_handshake(st)) {
		kassert(st->ssl);
		got = kgl_ssl_writev(st->ssl, recvBuf, bc);
	} else
#endif
		got = kgl_writev(st->fd, recvBuf, bc);
	if (got>=0) {
		return result(st->data,arg,got);
	}
#ifdef KSOCKET_SSL
	if (selectable_is_ssl_handshake(st)) {
		kassert(st->ssl);
		KBIT_CLR(st->st_flags, STF_WREADY);
		int err = SSL_get_error(st->ssl->ssl, got);
		if (errno == EAGAIN || err == SSL_ERROR_WANT_WRITE) {
#ifdef ENABLE_KSSL_BIO
			if (!selectable_ssl_write(st, result, buffer, arg)) {
				return result(st->data,arg, got);
			}
			return kev_ok;
#endif
			if (!kgl_selector_module.write(st->selector, st, result, buffer, arg)) {
				return result(st->data,arg, got);
			}
			return kev_ok;
		}
	}
#endif
	if (errno==EAGAIN) {
		KBIT_CLR(st->st_flags,STF_WREADY);
		if (kgl_selector_module.write(st->selector, st, result, buffer, arg)) {
			return kev_ok;
		}
	}
	return result(st->data,arg, got);
}
kev_result selectable_event_read(kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	assert(!KBIT_TEST(st->st_flags,STF_UDP));
	if (KBIT_TEST(st->st_flags, STF_RREADY2)) {
		KBIT_CLR(st->st_flags, STF_RREADY2);
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
	if (unlikely(buffer==NULL)) {
		return result(st->data,arg,0);
	}
	WSABUF recvBuf[MAXSENDBUF];
	int bc = buffer(st->data, arg, recvBuf, MAXSENDBUF);
	kassert(recvBuf[0].iov_len>0);
	int got;
#ifdef KSOCKET_SSL
	if (selectable_is_ssl_handshake(st)) {
		kassert(st->ssl);
		got = kgl_ssl_readv(st->ssl, recvBuf, bc); 
	} else 
#endif
		got = kgl_readv(st->fd, recvBuf, bc);

	if (got>=0) {
		return result(st->data, arg, got);
	}
#ifdef KSOCKET_SSL
	if (selectable_is_ssl_handshake(st)) {
		kassert(st->ssl);
		KBIT_CLR(st->st_flags, STF_RREADY);
		int err = SSL_get_error(st->ssl->ssl, got); 
		if (errno == EAGAIN || err == SSL_ERROR_WANT_READ) {
#ifdef ENABLE_KSSL_BIO
			if (!selectable_ssl_read(st, result, buffer, arg)) {
				return result(st->data, arg, got);
			}
			return kev_ok;
#endif
			if (kgl_selector_module.read(st->selector, st, result, buffer, arg)) {
				return kev_ok;
			}
		}
		return result(st->data, arg, got);
	}
#endif
	if (errno==EAGAIN) {
		kassert(!KBIT_TEST(st->st_flags, STF_RREADY2));
		KBIT_CLR(st->st_flags,STF_RREADY);
		if (kgl_selector_module.read(st->selector, st, result, buffer, arg)) {
			return kev_ok;
		}
	}
	return result(st->data, arg, got);
}
int selectable_sync_read(kselectable *st, LPWSABUF buf, int bc)
{
#ifdef KSOCKET_SSL
	if (selectable_is_ssl_handshake(st)) {
		kassert(st->ssl);
		return kgl_ssl_readv(st->ssl, buf, bc);
	}
#endif
	return kgl_readv(st->fd, buf, bc);
}
int selectable_sync_write(kselectable *st, LPWSABUF buf, int bc)
{

#ifdef KSOCKET_SSL
	if (selectable_is_ssl_handshake(st)) {
		kassert(st->ssl);
		return kgl_ssl_writev(st->ssl, buf, bc);
	}
#endif
	return kgl_writev(st->fd, buf, bc);
}
void selectable_add_sync(kselectable *st)
{
	selectable_remove(st);
	kselector_add_list(st->selector, st, KGL_LIST_SYNC);
#if 0
	int tmo = (st->tmo + 1) * st->selector->timeout[KGL_LIST_RW];
	ksocket_set_time(st->fd, tmo,tmo);
#ifndef KGL_IOCP
	ksocket_block(st->fd);
#endif
#endif
}
void selectable_remove_sync(kselectable *st)
{
	kselector_remove_list(st->selector, st);
}
bool selectable_readhup(kselectable *st, result_callback result, void *arg)
{
	if (kgl_selector_module.readhup) {
		return kgl_selector_module.readhup(st->selector, st, result, arg);
	}
	return false;
}
void selectable_remove_readhup(kselectable *st)
{
	if (kgl_selector_module.remove_readhup) {
		kgl_selector_module.remove_readhup(st->selector, st);
	}
}

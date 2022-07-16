#include <assert.h>
#include <string.h>
#include "kconnection.h"
#include "ksocket.h"
#include "kserver.h"
#include "kselector.h"
#include "kssl_bio.h"
#include "kmalloc.h"
#include "kfiber.h"

#ifdef KSOCKET_SSL
typedef struct {
	kconnection *c;
	result_callback cb;
	void *arg;
} kconnection_ssl_param;

extern kgl_ssl_create_sni_f kgl_ssl_create_sni;
extern kgl_ssl_free_sni_f kgl_ssl_free_sni;
static kev_result ssl_handshake_result(kconnection_ssl_param *sh, bool result)
{
	kev_result ret = sh->cb(sh->c->st.data, sh->arg, result ? 0 : -1);
	xfree(sh);
	return ret;
}
#endif

int kconnection_buffer_addr(KOPAQUE data, void *arg, WSABUF *buffer, int bc)
{
	kconnection* c = kgl_list_data(arg, kconnection, st);
	buffer[0].iov_base = (char *)&c->addr;
	buffer[0].iov_len = ksocket_addr_len(&c->addr);
	return 1;
}

kconnection* kconnection_internal_new()
{
	kconnection* c = (kconnection*)xmalloc(sizeof(kconnection));
	memset(c, 0, sizeof(kconnection));
	c->pool = kgl_create_pool(8192);
	ksocket_init(c->st.fd);
	return c;
}
kconnection* kconnection_new3(const struct sockaddr* addr, socklen_t addr_len)
{
	kconnection* c = kconnection_internal_new();
	kgl_memcpy(&c->addr, addr, MIN(addr_len,sizeof(sockaddr_i)));
	return c;
}
kconnection* kconnection_new2(struct addrinfo* ai, uint16_t port)
{
	kconnection* c = kconnection_internal_new();
	ksocket_addrinfo_sockaddr(ai, port, &c->addr);
	return c;
}
kconnection *kconnection_new(sockaddr_i *addr)
{
	kconnection* c = kconnection_internal_new();
	if (addr) {
#ifdef KSOCKET_UNIX
		if (addr->v4.sin_family==PF_UNIX) {
			c->addr.u.sin_family = PF_UNIX;
			c->addr.u.size = (short)sizeof(struct sockaddr_un);
			c->addr.u.addr = (struct sockaddr *)kgl_pnalloc(c->pool,(int)c->addr.u.size);
			memcpy(c->addr.u.addr,addr,c->addr.u.size);
		} else
#endif
		kgl_memcpy(&c->addr, addr, sizeof(sockaddr_i));
	}
	return c;
}
void kconnection_real_destroy(kconnection *c)
{
	selectable_clean(&c->st);
#ifdef KSOCKET_SSL
	if (c->sni) {
		kgl_ssl_free_sni(c->sni);
	}
#endif
	if (c->server) {
		if (KBIT_TEST(c->st.st_flags,STF_UDP)) {
			xfree(c->udp);
		} else {
			kserver_release(c->server);
		}		
	}
	kgl_destroy_pool(c->pool);
	xfree(c);
}
#ifdef KSOCKET_SSL
static kev_result result_ssl_shutdown(KOPAQUE data, void *arg, int got)
{
	kconnection*c = (kconnection*)arg;
	if (got == 0) {
		return kselectable_ssl_shutdown((kselectable*)&c->st, result_ssl_shutdown, c);
	}
	kconnection_real_destroy(c);
	return kev_destroy;
}
#endif
kev_result kconnection_destroy(kconnection *c)
{
#ifdef KSOCKET_SSL
	if (kconnection_is_ssl_handshake(c) && !c->st.ssl->shutdown) {
		c->st.data = NULL;
		if (!KBIT_TEST(c->st.st_flags, STF_ERR)) {
			return kselectable_ssl_shutdown(&c->st, result_ssl_shutdown, c);
		}
	}
#endif
	kconnection_real_destroy(c);
	return kev_destroy;
}
bool kconnection_half_connect(kconnection *c, sockaddr_i *bind_addr, int tproxy_mask)
{
#ifdef KSOCKET_UNIX
	if (c->addr.u.sin_family==PF_UNIX) {
		c->st.fd = ksocket_half_connect((sockaddr_i *)c->addr.u.addr, NULL, 0);
	} else
#endif
	c->st.fd = ksocket_half_connect(&c->addr, bind_addr, tproxy_mask);
	return ksocket_opened(c->st.fd);
}
kev_result kconnection_connect(kconnection *c,result_callback cb, void *arg)
{
	kassert(kfiber_check_result_callback(cb));
	assert(kselector_is_same_thread(c->st.selector));
#ifdef KGL_IOCP
	c->st.e[OP_READ].buffer = kconnection_buffer_addr;
	c->st.e[OP_READ].arg = &c->st;
#endif
	if (!kgl_selector_module.connect(c->st.selector, &c->st, cb, arg)) {
		return cb(c->st.data, arg, -1);
	}
	return kev_ok;
}
#ifdef KSOCKET_SSL
kev_result kselectable_ssl_shutdown(kselectable* st, result_callback cb, void* arg)
{
	kassert(ksocket_opened(st->fd));
	kssl_status status = kgl_ssl_shutdown(st->ssl->ssl);
#ifdef ENABLE_KSSL_BIO
	if (status != ret_error && BIO_pending(st->ssl->bio[OP_WRITE].bio) > 0) {
		return selectable_write(st, cb, NULL, arg);
	}
#endif
	switch (status) {
	case SSL_ERROR_WANT_READ:
#ifndef ENABLE_KSSL_BIO
		selectable_clear_flags(st, STF_RREADY);
#endif
		return selectable_read(st, cb, NULL, arg);
	case SSL_ERROR_WANT_WRITE:
#ifndef ENABLE_KSSL_BIO
		selectable_clear_flags(st, STF_WREADY);
#endif
		return selectable_write(st, cb, NULL, arg);
	default:
		return cb(st->data, arg, 1);
	}
}
kev_result kselectable_ssl_handshake(kselectable *st,result_callback cb, void *arg) 
{
	kssl_session* ssl = st->ssl;
	kassert(ssl);
	kssl_status status;
#ifdef SSL_READ_EARLY_DATA_SUCCESS
	if (ssl->try_early_data) {
		u_char     buf;
		size_t     readbytes = 0;
		int n = SSL_read_early_data(ssl->ssl, &buf, 1, &readbytes);
		//printf("sh=[%p %p] SSL_read_early_data=[%d]\n", sh,ssl->ssl,n);
		if (n == SSL_READ_EARLY_DATA_FINISH) {
			ssl->try_early_data = 0;
			status = kgl_ssl_handshake(ssl->ssl);
			goto check_status;
		}
		if (n == SSL_READ_EARLY_DATA_SUCCESS) {
			ssl->try_early_data = 0;
			ssl->early_buf = buf;
			ssl->in_early = 1;
			ssl->early_preread = 1;
			//printf("read early data buf=[%c] arg=[%p]\n",buf,sh->arg);
			return cb(st->data, arg, 1); 
		}
		status = kgl_ssl_handshake_status(ssl->ssl, n);
	} else
#endif
	status = kgl_ssl_handshake(ssl->ssl);

check_status:
#ifdef ENABLE_KSSL_BIO
	if (status != ret_error && BIO_pending(ssl->bio[OP_WRITE].bio) > 0) {
		//want write
		return selectable_write(st, cb, NULL, arg);
	}
#endif
	switch (status) {
	case ret_ok:
		return cb(st->data, arg, 1);
	case ret_want_read:
#ifndef ENABLE_KSSL_BIO
		selectable_clear_flags(st, STF_RREADY);
#endif
		return selectable_read(st, cb, NULL, arg);
	case ret_want_write:
#ifndef ENABLE_KSSL_BIO
		selectable_clear_flags(st, STF_WREADY);
#endif
		return selectable_write(st, cb, NULL, arg);
	default:
		return cb(st->data, arg, -1);
	}
}

static kev_result result_ssl_handshake(KOPAQUE data, void *arg, int got)
{
	kconnection_ssl_param* sh = (kconnection_ssl_param*)arg;
	switch (got) {
	case -1:
		return ssl_handshake_result(sh, false);
	case 1:
		return ssl_handshake_result(sh, true);
	default:
		return kselectable_ssl_handshake(&sh->c->st, result_ssl_handshake, sh);
	}
}
static void kconnection_ssl_init(kconnection *c,SSL_CTX *ssl_ctx, SSL *ssl)
{
	kassert(c->st.ssl == NULL);
	c->st.ssl = xmemory_new(kssl_session);
	memset(c->st.ssl, 0, sizeof(kssl_session));
#ifdef ENABLE_KSSL_BIO
	c->st.ssl->bio[0].bio = BIO_new(BIO_kgl_method());
	c->st.ssl->bio[1].bio = BIO_new(BIO_kgl_method());
	SSL_set_bio(ssl, c->st.ssl->bio[OP_READ].bio, c->st.ssl->bio[OP_WRITE].bio);
#endif
	c->st.ssl->ssl = ssl;
#ifdef SSL_READ_EARLY_DATA_SUCCESS
	if (SSL_CTX_get_max_early_data(ssl_ctx)) {
		c->st.ssl->try_early_data = 1;
	}
#endif
}
kev_result kconnection_ssl_handshake(kconnection *c,result_callback cb, void *arg)
{	
	kassert(kfiber_check_result_callback(cb));
	kconnection_ssl_param *sh = xmemory_new(kconnection_ssl_param);
	memset(sh, 0, sizeof(kconnection_ssl_param));
	sh->c = c;
	sh->cb = cb;
	sh->arg = arg;
	c->st.ssl->handshake = 1;
	return kselectable_ssl_handshake(&c->st, result_ssl_handshake, sh);
}
kev_result kconnection_ssl_shutdown(kconnection *c, result_callback cb, void *arg)
{
	kassert(kfiber_check_result_callback(cb));
	kconnection_ssl_param *sh = xmemory_new(kconnection_ssl_param);
	memset(sh, 0, sizeof(kconnection_ssl_param));
	sh->c = c;
	sh->cb = cb;
	sh->arg = arg;
	return result_ssl_shutdown(NULL, sh, 0);
}
static SSL *kconnection_new_ssl(kconnection *c,SSL_CTX *ssl_ctx)
{
	SSL *ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {		
		return NULL;
	}
	if (SSL_set_fd(ssl, (int)c->st.fd) != 1) {
		SSL_free(ssl);		
		return NULL;
	}
	return ssl;
}
bool kconnection_ssl_connect(kconnection *c, SSL_CTX *ssl_ctx, const char *sni_hostname)
{
	SSL *ssl = kconnection_new_ssl(c, ssl_ctx);
	if (ssl == NULL) {
		return false;
	}
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	if (sni_hostname) {
		SSL_set_tlsext_host_name(ssl, sni_hostname);
	}
#endif
	SSL_set_connect_state(ssl);
	kconnection_ssl_init(c, ssl_ctx, ssl);
	return true;
}

bool kconnection_ssl_accept(kconnection *c, SSL_CTX *ssl_ctx)
{
	SSL *ssl = kconnection_new_ssl(c, ssl_ctx);
	if (ssl == NULL) {
		return false;
	}
	SSL_set_accept_state(ssl);
	SSL_set_ex_data(ssl, kangle_ssl_conntion_index, c);
	kconnection_ssl_init(c, ssl_ctx, ssl);
	return true;
}
#endif

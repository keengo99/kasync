#ifndef MSOCKET_KSERVER_SELECTABLE_H
#define MSOCKET_KSERVER_SELECTABLE_H
#include <assert.h>
#include "kfeature.h"
#include "kselectable.h"
#include "ksocket.h"
#include "kconnection.h"
#include "kmalloc.h"
#include "kgl_ssl.h"
#include "kcountable.h"
KBEGIN_DECLS
typedef void (*kserver_accept_callback)(kconnection *c,void *ctx);
typedef void (*kserver_close_callback)(void *ctx);


struct kserver_selectable_s{
	kselectable st;
	kserver *server;
#ifdef KSOCKET_SSL
	kgl_ssl_ctx *ssl_ctx;
#endif
	kserver_selectable *next;
	sockaddr_i accept_addr;
	socklen_t addr_len;
#ifdef _WIN32
	char *tmp_addr_buf;
	SOCKET accept_sockfd;
#endif
};
struct kserver_s {
	kcountable_t refs;
	kserver_accept_callback accept_callback;
	kserver_close_callback  close_callback;
	void *ctx;
	kserver_selectable *ss;
#ifdef KSOCKET_UNIX
	union {
		sockaddr_i addr;
		struct sockaddr_un un_addr;
	};
#else
	sockaddr_i addr;
#endif
#ifdef KSOCKET_SSL
	bool http2;
	bool early_data;
#endif
	uint8_t flags;
	uint8_t ssl : 1;
	uint8_t closed:1;
	uint8_t started:1;
	uint8_t dynamic:1;
	uint8_t global:1;
};
INLINE bool is_server_multi_selectable(kserver *server) {
	kassert(server->ss);
	return (server->ss->next != NULL);
}
kserver *kserver_init();

void kserver_bind(kserver *server,kserver_accept_callback accept_callback, kserver_close_callback close_callback, void *ctx);
bool kserver_open(kserver *server, const char *ip, uint16_t port, int flag, kgl_ssl_ctx *ssl_ctx);
//only bind address not open
bool kserver_bind_address(kserver *server, const char *ip, uint16_t port, int flag, kgl_ssl_ctx *ssl_ctx);
kserver_selectable *kserver_listen(kserver *server);
void kserver_accept2(kserver_selectable *ss,result_callback accept_callback,void *arg);
void kserver_close2(kserver_selectable *ss);
void kserver_shutdown(kserver_selectable *ss);
void kserver_close(kserver *server);
void kserver_release(kserver *server);
bool kserver_accept(kserver *server);
#ifdef KSOCKET_SSL
//bool kserver_open_ssl(kserver *server, const char *ip, uint16_t port, int flag, SSL_CTX *ssl_ctx);
void kserver_set_ssl_ctx(kserver *server,kgl_ssl_ctx *ssl_ctx);
INLINE SSL_CTX *kserver_selectable_get_ssl_ctx(kserver_selectable *ss)
{
	if (ss->ssl_ctx == NULL) {
		return NULL;
	}
	return kgl_get_ssl_ctx(ss->ssl_ctx);
}
INLINE SSL_CTX *kserver_get_ssl_ctx(kserver *server)
{
	if (server->ss == NULL) {
		return NULL;
	}
	return kserver_selectable_get_ssl_ctx(server->ss);
}
#endif
INLINE void kserver_refs(kserver *server)
{
	katom_inc((void *)&server->refs);
}
KEND_DECLS
#endif

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
#define IS_VALIDE_CONNECTION(got) (got>=0)

#define KACCEPT_CALLBACK_DECLEAR(fn)\
kev_result fn(KOPAQUE data, void *arg, int got)

#define KACCEPT_CALLBACK(fn)\
static kev_result user_##fn##(KOPAQUE data, void *arg, int got);\
kev_result fn##(KOPAQUE data, void *arg, int got) { \
	assert(arg==NULL);\
	kserver_selectable *ss = (kserver_selectable *)data;\
	assert(ss->st.selector == kgl_get_tls_selector());\
	kconnection *cn = accept_result_new_connection(data,got);\
	if (cn==NULL) {\
		kserver_selectable_destroy(ss);\
		return kev_ok;\
	}\
	cn->st.selector = kserver_get_perfect_selector(ss);\
	if (cn->st.selector!=ss->st.selector) {\
		kgl_selector_module.next(cn->st.selector, data, user_##fn##, cn, got);\
	} else {\
		user_##fn##(data, cn, got);\
	}\
	if (ss->server->closed || !kserver_selectable_accept(ss, arg)) {\
		kserver_selectable_destroy(ss); \
	}\
	return kev_ok;\
}\
kev_result user_##fn##(KOPAQUE data, void *arg, int got)

KBEGIN_DECLS

typedef void (*kserver_free_opaque)(KOPAQUE data);


struct kserver_selectable_s{
	kselectable st;
	kserver *server;
#ifdef KSOCKET_SSL
	kgl_ssl_ctx *ssl_ctx;
#endif
	kgl_list queue;
	sockaddr_i accept_addr;
	socklen_t addr_len;
#ifdef _WIN32
	char *tmp_addr_buf;
	SOCKET accept_sockfd;
#endif
};
struct kserver_s {
	kcountable_t refs;
	kserver_free_opaque  free_opaque;
	KOPAQUE data;
	kgl_list ss;
#ifdef KSOCKET_UNIX
	union {
		sockaddr_i addr;
		struct sockaddr_un un_addr;
	};
#else
	sockaddr_i addr;
#endif
#ifdef KSOCKET_SSL
	kgl_ssl_ctx* ssl_ctx;
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
	kgl_list *ss_list =  klist_head(&server->ss);
	if (ss_list == &server->ss) {
		return false;
	}
	return ss_list->next != &server->ss;
}
kserver *kserver_init();
INLINE bool is_server_supported_multi_selectable()
{
#ifdef _WIN32
	return false;
#else
	return true;
#endif
}
//only bind address not open
INLINE void kserver_set_opaque(kserver* server, kserver_free_opaque free_opaque, KOPAQUE data)
{
	server->free_opaque = free_opaque;
	server->data = data;
}
INLINE KOPAQUE kserver_get_opaque(kserver* server) {
	return server->data;
}
bool kserver_bind(kserver *server, const char *ip, uint16_t port, kgl_ssl_ctx *ssl_ctx);
bool kserver_open(kserver* server, int flag, result_callback accept_callback);
kserver_selectable *kserver_listen(kserver *server, int flag, result_callback accept_callback);
bool kserver_selectable_accept(kserver_selectable *ss, void *arg);
void kserver_selectable_destroy(kserver_selectable *ss);
kconnection* accept_result_new_connection(KOPAQUE data, int got);

void kserver_shutdown(kserver* server);
//kserver_close并不会释放server,释放server要调用kserver_release
void kserver_close(kserver *server);
void kserver_release(kserver *server);


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
	kgl_list* ss_list = klist_head(&server->ss);
	if (ss_list == &server->ss) {
		return NULL;
	}

	return kserver_selectable_get_ssl_ctx(kgl_list_data(ss_list, kserver_selectable, queue));
}
#endif
kselector* kserver_get_perfect_selector(kserver_selectable* ss);
INLINE void kserver_refs(kserver *server)
{
	katom_inc((void *)&server->refs);
}
KEND_DECLS
#endif

#ifndef MSOCKET_KSERVER_SELECTABLE_H
#define MSOCKET_KSERVER_SELECTABLE_H
#include <assert.h>
#include "kfeature.h"
#include "kselectable.h"
#include "ksocket.h"
#include "kconnection.h"
#include "kmalloc.h"
#include "kgl_ssl.h"
#include "ksync.h"
#define KGL_SERVER_SSL         (1<<31)
#define KGL_SERVER_START       (1<<30)
#define KGL_SERVER_UNIX        (1<<29)
#define KGL_SERVER_H2          (1<<28)
#define KGL_SERVER_REJECT_NOSNI (1<<27)

//#define KGL_SSL_CTX_EARLY_DATA (1<<28)
#ifndef _WIN32
#define MULTI_SERVER_SELECTABLE_SUPPORTED 1
#endif
#define IS_VALIDE_CONNECTION(got) (got>=0)

#ifdef DARWIN
//accept socket call shutdown no event return from kernel.
#define ACCEPT_SOCKET_SHUTDOWN_NO_EVENT
#endif


#define KACCEPT_CALLBACK_DECLEAR(fn)\
kev_result fn(KOPAQUE data, void *arg, int got)

#define KACCEPT_CALLBACK(fn)\
static kev_result user_##fn##_callback(KOPAQUE data, void *arg, int got);\
kev_result fn(KOPAQUE data, void *arg, int got) { \
	assert(arg==NULL);\
	kserver_selectable *ss = (kserver_selectable *)data;\
	assert(ss->st.base.selector == kgl_get_tls_selector());\
	kconnection *cn = accept_result_new_connection(data,got);\
	if (cn==NULL) {\
		kserver_selectable_destroy(ss);\
		return kev_ok;\
	}\
	selectable_bind(&cn->st, kserver_get_perfect_selector(ss));\
	if (cn->st.base.selector!=ss->st.base.selector) {\
		kgl_selector_module.next(cn->st.base.selector, data, user_##fn##_callback, cn, got);\
	} else {\
		user_##fn##_callback(data, cn, got);\
	}\
	if (!KBIT_TEST(ss->server->flags,KGL_SERVER_START) || !kserver_selectable_accept(ss, arg)) {\
		kserver_selectable_destroy(ss); \
	}\
	return kev_ok;\
}\
kev_result user_##fn##_callback(KOPAQUE data, void *arg, int got)

KBEGIN_DECLS

typedef void (*kserver_free_opaque)(KOPAQUE data);


struct kserver_selectable_s{
	kselectable st;
	kserver *server;
#ifdef KSOCKET_SSL
	kgl_ssl_ctx *ssl_ctx;
#endif
	kgl_list queue;
#ifdef ACCEPT_SOCKET_SHUTDOWN_NO_EVENT
	volatile int32_t hold_by_next_shutdown_refs;
#endif
	sockaddr_i accept_addr;
	socklen_t addr_len;
#ifdef _WIN32
	char *tmp_addr_buf;
	SOCKET accept_sockfd;
#endif
};
struct kserver_s {
	kcountable_t refs;
	volatile uint32_t flags;
	kserver_free_opaque  free_opaque;
	KOPAQUE data;
	kgl_list ss;
	kmutex ss_lock;
#ifdef KSOCKET_SSL
	kgl_ssl_ctx* ssl_ctx;
#endif
#ifdef KSOCKET_UNIX
	union {
		sockaddr_i addr;
		struct sockaddr_un un_addr;
	};
#else
	sockaddr_i addr;
#endif
};
bool is_server_multi_selectable(kserver *server);
DLL_PUBLIC kserver *kserver_init();
INLINE bool is_server_supported_multi_selectable()
{
#ifdef MULTI_SERVER_SELECTABLE_SUPPORTED
	return true;
#else
	return false;
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
DLL_PUBLIC bool kserver_bind(kserver *server, const char *ip, uint16_t port, kgl_ssl_ctx *ssl_ctx);
DLL_PUBLIC bool kserver_open(kserver* server, int flag, result_callback accept_callback);
DLL_PUBLIC bool kserver_open_exsit(kserver* server, SOCKET sockfd, result_callback accept_callback);
DLL_PUBLIC kserver_selectable *kserver_listen(kserver *server, int flag, result_callback accept_callback);
DLL_PUBLIC bool kserver_selectable_accept(kserver_selectable *ss, void *arg);
DLL_PUBLIC void kserver_selectable_destroy(kserver_selectable *ss);
DLL_PUBLIC kconnection* accept_result_new_connection(KOPAQUE data, int got);
INLINE void kgl_set_flag(uint32_t *flags, int flag, bool val) {
	if (val) {
		KBIT_SET(*flags, flag);
	} else {
		KBIT_CLR(*flags, flag);
	}
}
INLINE uint32_t kserver_test_flag(kserver* server, uint32_t flag) {
	return KBIT_TEST(server->flags, flag);
}
//NOTICE: kserver_close will not release server,release server must call kserver_release
DLL_PUBLIC void kserver_close(kserver *server);
#define kserver_shutdown kserver_close
DLL_PUBLIC void kserver_release(kserver *server);

#ifdef KSOCKET_SSL
//bool kserver_open_ssl(kserver *server, const char *ip, uint16_t port, int flag, SSL_CTX *ssl_ctx);
DLL_PUBLIC void kserver_set_ssl_ctx(kserver *server,kgl_ssl_ctx *ssl_ctx);
INLINE SSL_CTX *kserver_selectable_get_ssl_ctx(kserver_selectable *ss)
{
	if (ss->ssl_ctx == NULL) {
		return NULL;
	}
	return kgl_get_ssl_ctx(ss->ssl_ctx);
}
INLINE SSL_CTX *kserver_get_ssl_ctx(kserver *server)
{
	if (server->ssl_ctx==NULL) {
		return NULL;
	}
	return kgl_get_ssl_ctx(server->ssl_ctx);
}
#endif
DLL_PUBLIC kselector* kserver_get_perfect_selector(kserver_selectable* ss);
INLINE void kserver_refs(kserver *server)
{
	katom_inc((void *)&server->refs);
}
KEND_DECLS
#endif

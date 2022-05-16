#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include "kfeature.h"
#include "kmalloc.h"
#include "kserver.h"
#include "klog.h"
#include "klib.h"
#include "kselector_manager.h"
#ifdef _WIN32
#include "kiocp_selector.h"
#endif
#include "kfiber.h"

#ifdef KSOCKET_SSL
typedef struct {
	kserver_selectable *ss;
	kgl_ssl_ctx *ssl_ctx;
} kserver_update_ssl_ctx_param;
#endif

static int kgl_failed_tries = 0;

#ifndef KGL_IOCP
kev_result kselector_event_accept(KOPAQUE data, void *arg,int got)
{
	kserver_selectable *ss = (kserver_selectable *)arg;
	//printf("ksocket_accept called...\n");
	SOCKET sockfd = ksocket_accept(ss->st.fd,&ss->accept_addr, true);
	
	if (sockfd>=0) {
		//printf("ksocket_accept=[%d]\n",sockfd);
		return ss->st.e[OP_WRITE].result(data, ss->st.e[OP_WRITE].arg,(int)sockfd);
	}
	if (errno==EAGAIN && !KBIT_TEST(ss->st.st_flags,STF_ERR)) {
		//printf("try again\n");
		assert(!KBIT_TEST(ss->st.st_flags, STF_RREADY2));
		KBIT_CLR(ss->st.st_flags,STF_RREADY);
		if (kgl_selector_module.accept(ss->st.selector, ss, ss->st.e[OP_WRITE].arg)) {
			return kev_ok;
		}
	}
	//printf("accept failed.\n");
	return ss->st.e[OP_WRITE].result(data, ss->st.e[OP_WRITE].arg,(int)sockfd);	
}
#endif

static SOCKET kserver_get_socket(kserver_selectable* ss, int got)
{
#ifndef _WIN32
	return got;
#else
	SOCKET sockfd;
	if (got < 0) {
		ksocket_close(ss->accept_sockfd);
		ksocket_init(sockfd);
	} else {
		sockfd = ss->accept_sockfd;
	}
	ksocket_init(ss->accept_sockfd);
	return sockfd;
#endif
}
kselector* kserver_get_perfect_selector(kserver_selectable* ss) {
	if (is_server_multi_selectable(ss->server)) {
		return ss->st.selector;
	}
	return get_perfect_selector();
}
kconnection* accept_result_new_connection(KOPAQUE data,int got)
{
	kserver_selectable* ss = (kserver_selectable*)data;
	SOCKET sockfd = kserver_get_socket(ss, got);
	if (!ksocket_opened(sockfd)) {
		return NULL;
	}
	kconnection* c = kconnection_new(&ss->accept_addr);
	c->st.fd = sockfd;
	c->server = ss->server;
	kserver_refs(ss->server);	
#ifdef KSOCKET_SSL
	SSL_CTX* ssl_ctx = kserver_selectable_get_ssl_ctx(ss);
	if (ssl_ctx) {
		if (!kconnection_ssl_accept(c, ssl_ctx)) {
			klog(KLOG_ERR, "cann't create ssl object\n");
			kconnection_real_destroy(c);
			return NULL;
		}
	}
#endif
	return c;
};
bool is_server_multi_selectable(kserver *server) {
	bool result;
	kmutex_lock(&server->ss_lock);
	kgl_list *ss_list =  klist_head(&server->ss);
	if (ss_list == &server->ss) {
		result = false;
	} else {
		result = (ss_list->next != &server->ss);
	}
	kmutex_unlock(&server->ss_lock);
	return result;
}
kserver *kserver_init()
{
	kserver *server = xmemory_new(kserver);
	memset(server, 0, sizeof(kserver));
	server->refs = 1;
	klist_init(&server->ss);
	kmutex_init(&server->ss_lock,NULL);
	return server;
}
void kserver_selectable_free(kserver_selectable *ss) {
#ifdef _WIN32
	if (ksocket_opened(ss->accept_sockfd)) {
		ksocket_close(ss->accept_sockfd);
	}
	xfree(ss->tmp_addr_buf);
#endif
	if (ksocket_opened(ss->st.fd)) {
		ksocket_close(ss->st.fd);
#ifdef KSOCKET_UNIX	
		if (ss->server->addr.v4.sin_family==AF_UNIX) {
			const char *unix_path = ksocket_unix_path(&ss->server->un_addr);
			unlink(unix_path);
		}
#endif
	}
#ifdef KSOCKET_SSL
	if (ss->ssl_ctx) {
		kgl_release_ssl_ctx(ss->ssl_ctx);
	}
#endif
	xfree(ss);
}
bool kserver_selectable_accept(kserver_selectable* ss, void *arg)
{
	assert(ss->st.data == ss);
	assert(ss->st.e[STF_READ].result != NULL);
	return	kgl_selector_module.accept(ss->st.selector, ss, arg);
}
kserver_selectable *kserver_selectable_init(kserver *server, SOCKET sockfd)
{
	kserver_selectable *ss = (kserver_selectable *)xmalloc(sizeof(kserver_selectable));
	memset(ss, 0, sizeof(kserver_selectable));
	ss->server = server;
	ss->st.fd = sockfd;
#ifdef _WIN32
	ss->tmp_addr_buf = (char *)xmalloc(2 * sizeof(sockaddr_i) + 64);
	ksocket_init(ss->accept_sockfd);
#endif
	kserver_refs(server);
#ifdef KSOCKET_SSL
	ss->ssl_ctx = server->ssl_ctx;
	if (ss->ssl_ctx) {
		kgl_add_ref_ssl_ctx(ss->ssl_ctx);
	}
#endif
	return ss;
}
kserver_selectable *add_server_socket(kserver *server,SOCKET sockfd)
{
	kserver_selectable *ss = kserver_selectable_init(server, sockfd);
	kmutex_lock(&server->ss_lock);
	klist_append(&server->ss, &ss->queue);
	kmutex_unlock(&server->ss_lock);
	return ss;
}
static kserver_selectable* kserver_listen_on_selector(kselector *selector, kserver* server, int flag, result_callback accept_callback)
{
	KBIT_SET(flag, KSOCKET_REUSEPORT);
	SOCKET sockfd;
	for (;;) {
		sockfd = ksocket_listen(&server->addr, flag);
		if (ksocket_opened(sockfd)) {
			break;
		}
		if (kgl_failed_tries > 10) {
			break;
		}
		kgl_failed_tries++;
		if (kfiber_self() == NULL) {
			kgl_msleep(500);
		} else {
			kfiber_msleep(500);
		}
	}
	if (!ksocket_opened(sockfd)) {
		return NULL;
	}
	if (ksocket_addr_port(&server->addr) == 0) {
		//update addr
		socklen_t addr_len = (socklen_t)ksocket_addr_len(&server->addr);
		getsockname(sockfd, (struct sockaddr*)&server->addr, &addr_len);
	}
	kserver_selectable* ss = add_server_socket(server, sockfd);
	if (ss == NULL) {
		return NULL;
	}
	ss->st.data = ss;
	ss->st.selector = selector;
	assert(ss->st.selector);
	kgl_selector_module.listen(ss->st.selector, ss, accept_callback);
	return ss;
}
kserver_selectable* kserver_listen(kserver* server, int flag, result_callback accept_callback)
{
	return kserver_listen_on_selector(kgl_get_tls_selector(), server, flag, accept_callback);
}

bool kserver_bind(kserver *server, const char *ip, uint16_t port, kgl_ssl_ctx *ssl_ctx)
{
#ifdef KSOCKET_SSL
	if (server->ssl && ssl_ctx == NULL) {
		return false;
	}
	if (ssl_ctx) {
		server->ssl = 1;
	}
#endif
	if (*ip=='/') {
#ifdef KSOCKET_UNIX	
		ksocket_unix_addr(ip,&server->un_addr);
#endif
	} else if (!ksocket_getaddr(ip, port, 0, AI_NUMERICHOST, &server->addr)) {
#ifdef KSOCKET_SSL
		if (ssl_ctx) {
			kgl_release_ssl_ctx(ssl_ctx);
		}
#endif
		return false;
	}
#ifdef KSOCKET_SSL
	kserver_set_ssl_ctx(server, ssl_ctx);
#endif
	return true;
}
static kev_result kserver_next_accept(KOPAQUE data, void* arg, int got)
{
	kserver_selectable* ss = (kserver_selectable*)arg;
	if (!kgl_selector_module.accept(kgl_get_tls_selector(), ss, NULL)) {
		kserver_selectable_destroy(ss);
	}
	return kev_ok;
}
static void kserver_selectable_start(kserver_selectable* ss) {

	if (ss->st.selector == kgl_get_tls_selector()) {
		kserver_next_accept(NULL, ss, 0);
	} else {
		selectable_next(&ss->st, kserver_next_accept, ss, 0);
	}
}
bool kserver_open_exsit(kserver* server, SOCKET sockfd, result_callback accept_callback)
{
	socklen_t addr_len = (socklen_t)sizeof(server->addr);
	if (0 != getsockname(sockfd, (struct sockaddr*)&server->addr, &addr_len)) {
		klog(KLOG_NOTICE, "error [%s:%d]\n", __FILE__, __LINE__);
		return false;
	}
	kserver_selectable* ss = add_server_socket(server, sockfd);
	if (ss == NULL) {
		klog(KLOG_NOTICE, "error [%s:%d]\n", __FILE__, __LINE__);
		return false;
	}
	ss->st.data = ss;
	ss->st.selector = kgl_get_tls_selector();
	assert(ss->st.selector);
	if (!kgl_selector_module.listen(ss->st.selector, ss, accept_callback)) {
		klog(KLOG_NOTICE, "error [%s:%d]\n", __FILE__, __LINE__);
		return false;
	}
	kserver_selectable_start(ss);
	return true;
}
bool kserver_open(kserver* server, int flag, result_callback accept_callback)
{
	KBIT_SET(flag, KSOCKET_REUSEPORT);
	int i;
	bool result = false;
	assert(!server->started);
	if (!is_server_supported_multi_selectable()) {
		kserver_selectable *ss = kserver_listen_on_selector(get_perfect_selector(), server, flag, accept_callback);
		if (ss != NULL) {
			server->started = true;
			result = true;
			kserver_selectable_start(ss);
		}
		return result;
	}
	int selector_count = get_selector_count();
	for (i = 0; i < selector_count; i++) {
		kserver_selectable* ss = kserver_listen_on_selector(get_selector_by_index(i), server, flag, accept_callback);
		if (ss != NULL) {
			result = true;
			server->started = true;
			kserver_selectable_start(ss);
		}
	}
	return result;
}
static void kserver_free(kserver *server) {
	assert(klist_empty(&server->ss));
	for (;;) {
		kgl_list* pos = klist_head(&server->ss);
		if (pos == &server->ss) {
			break;
		}
		klist_remove(pos);
		kserver_selectable* ss = kgl_list_data(pos, kserver_selectable, queue);
		kserver_selectable_free(ss);
	}
	if (server->free_opaque) {
		server->free_opaque(server->data);
	}
#ifdef KSOCKET_SSL
	if (server->ssl_ctx) {
		kgl_release_ssl_ctx(server->ssl_ctx);
	}
#endif
	kmutex_destroy(&server->ss_lock);
	xfree(server);
}
void kserver_release(kserver *server)
{
	if (katom_dec((void *)&server->refs) == 0) {
		kserver_free(server);
	}
	return;
}

void kserver_selectable_destroy(kserver_selectable *ss)
{
	if (ksocket_opened(ss->st.fd)) {
		ksocket_close(ss->st.fd);
		ksocket_init(ss->st.fd);
	}
	assert(ss->server);
	kmutex_lock(&ss->server->ss_lock);
	if (ss->queue.next) {
		assert(!klist_empty(&ss->server->ss));
		klist_remove(&ss->queue);
	}
	kmutex_unlock(&ss->server->ss_lock);
#ifdef ACCEPT_SOCKET_SHUTDOWN_NO_EVENT
	if(katom_get((void *)&ss->hold_by_next_shutdown_refs)>0) {
		//hold by next_shutdown
		printf("hold by next_shutdown st=[%p]\n",ss);
		return;
	}
#endif
	kserver_release(ss->server);
	kserver_selectable_free(ss);
}
kev_result kserver_selectable_next_shutdown(KOPAQUE data, void *arg,int got)
{
	kserver_selectable *ss = (kserver_selectable *)arg;
	//printf("next_shutdown arg=[%p] st=[%p] fd=[%d]\n",arg, &ss->st,ss->st.fd);
	int32_t refs = katom_dec((void *)&ss->hold_by_next_shutdown_refs);
	assert(refs==0);
	KBIT_SET(ss->st.st_flags,STF_RREADY|STF_ERR);
	if (!ksocket_opened(ss->st.fd)) {
		//already close
		kserver_selectable_destroy(ss);
		return kev_ok;
	}
	selectable_shutdown(&ss->st);
	kselector_add_list(ss->st.selector,&ss->st,KGL_LIST_READY);
}
void kserver_close(kserver* server)
{
	server->closed = true;
	kgl_list* pos;
	kmutex_lock(&server->ss_lock);
#ifdef ACCEPT_SOCKET_SHUTDOWN_NO_EVENT
	while (!klist_empty(&server->ss)) {
		pos = klist_head(&server->ss);
		kserver_selectable* ss = kgl_list_data(pos, kserver_selectable, queue);
		katom_inc((void *)&ss->hold_by_next_shutdown_refs);
		assert(ss->hold_by_next_shutdown_refs == 1);
		klist_remove(pos);
		pos->next = NULL;
		//printf("try next shutdown socket arg=[%p] st=[%p] fd=[%d]\n",ss, &ss->st, ss->st.fd);
		selectable_next(&ss->st, kserver_selectable_next_shutdown, ss, 0);
	}
#else
	klist_foreach(pos, &server->ss) {
		kserver_selectable* ss = kgl_list_data(pos, kserver_selectable, queue);
		selectable_shutdown(&ss->st);
	}
#endif
	kmutex_unlock(&server->ss_lock);
}
#ifdef KSOCKET_SSL
static void kserver_selectable_update_ssl_ctx(kserver_selectable *ss, kgl_ssl_ctx *ssl_ctx)
{
	if (ss->ssl_ctx) {
		kgl_release_ssl_ctx(ss->ssl_ctx);
	}
	ss->ssl_ctx = ssl_ctx;
}
static kev_result kserver_ssl_ctx_next_update(KOPAQUE data, void *arg, int got)
{
	kserver_update_ssl_ctx_param *param = (kserver_update_ssl_ctx_param *)arg;
	kserver_selectable_update_ssl_ctx(param->ss, param->ssl_ctx);
	xfree(param);
	return kev_ok;
}
void kserver_set_ssl_ctx(kserver *server, kgl_ssl_ctx *ssl_ctx)
{
	if (server->ssl_ctx && ssl_ctx == NULL) {
		//cann't set ssl_ctx to NULL
		return;
	}
	if (server->ssl_ctx) {
		kgl_release_ssl_ctx(server->ssl_ctx);
	}
	server->ssl_ctx = ssl_ctx;
	kmutex_lock(&server->ss_lock);
	kgl_list* pos;
	klist_foreach(pos, &server->ss) {
		kserver_selectable* ss = kgl_list_data(pos, kserver_selectable, queue);	
		if (ssl_ctx) {
			kgl_add_ref_ssl_ctx(ssl_ctx);
		}
		if (!server->started) {
			kserver_selectable_update_ssl_ctx(ss, ssl_ctx);
		} else {
			kserver_update_ssl_ctx_param *param = xmemory_new(kserver_update_ssl_ctx_param);
			param->ss = ss;
			param->ssl_ctx = ssl_ctx;
			selectable_next(&ss->st, kserver_ssl_ctx_next_update, param, 0);
		}
	}
	kmutex_unlock(&server->ss_lock);
}
#endif

#include <string.h>
#include <assert.h>
#include <errno.h>
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

int kgl_failed_tries = 0;
kev_result next_server_request(KOPAQUE data, void *arg, int got)
{
	kconnection *c = (kconnection *)arg;
	c->server->accept_callback(c,c->server->ctx);
	return kev_ok;
}
#ifndef KGL_IOCP
kev_result kselector_event_accept(KOPAQUE data, void *arg,int got)
{
	kserver_selectable *ss = (kserver_selectable *)arg;
	SOCKET sockfd = ksocket_accept(ss->st.fd,&ss->accept_addr, true);
	return ss->st.e[OP_WRITE].result(data, ss->st.e[OP_WRITE].arg,(int)sockfd);
}
#endif
void accept_result(kserver_selectable *ss, SOCKET sockfd, sockaddr_i *sockaddr)
{
#ifndef NDEBUG
	//klog(KLOG_DEBUG,"new client %s:%d connect to %s:%d sockfd=%d\n", socket->get_remote_ip().c_str(), socket->get_remote_port(),socket->get_self_ip().c_str(),socket->get_self_port(),socket->get_socket());
#endif

	kconnection *c = kconnection_new(sockaddr);	
	c->st.fd = sockfd;
	c->server = ss->server;
	kserver_refs(ss->server);	
	if (is_server_multi_selectable(ss->server)) {
		c->st.selector = ss->st.selector;
	} else {
		c->st.selector = get_perfect_selector();
	}
#ifdef KSOCKET_SSL
	SSL_CTX *ssl_ctx = kserver_selectable_get_ssl_ctx(ss);
	if (ssl_ctx) {
		if (!kconnection_ssl_accept(c,ssl_ctx)) {
			klog(KLOG_ERR, "cann't create ssl object\n");
			kconnection_destroy(c);
			return;
		}
	}
#endif
	if (ss->st.selector == c->st.selector) {
		c->server->accept_callback(c,c->server->ctx);
		return;
	}
	selectable_next(&c->st, next_server_request, c,0);
}
SOCKET kserver_get_socket(kserver_selectable *ss, int got)
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
kev_result handle_server_listen(KOPAQUE data, void *arg, int got)
{
	kserver_selectable *ss = (kserver_selectable *)arg;
	SOCKET sockfd = kserver_get_socket(ss, got);
	if (ksocket_opened(sockfd)) {
		accept_result(ss,sockfd,&ss->accept_addr);
	} else {
		klog(KLOG_ERR, "cann't accept connect,errno=[%d]\n", errno);
	}
	if (ss->server->closed) {
		selectable_remove(&ss->st);
		ss->server->started = false;
		kserver_release(ss->server);
		return kev_destroy;
	}
	return kev_ok;
}
kserver *kserver_init()
{
	kserver *server = xmemory_new(kserver);
	memset(server, 0, sizeof(kserver));
	server->refs = 1;
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
kserver_selectable *kserver_selectable_init(kserver *server, SOCKET sockfd)
{
	kserver_selectable *ss = (kserver_selectable *)malloc(sizeof(kserver_selectable));
	memset(ss, 0, sizeof(kserver_selectable));
	ss->server = server;
	ss->st.fd = sockfd;
#ifdef _WIN32
	ss->tmp_addr_buf = (char *)xmalloc(2 * sizeof(sockaddr_i) + 64);
	ksocket_init(ss->accept_sockfd);
#endif
	return ss;
}
void add_server_socket(kserver *server,SOCKET sockfd)
{
	kserver_selectable *ss = kserver_selectable_init(server, sockfd);
	ss->next = server->ss;
	server->ss = ss;
}
bool kserver_internal_open(kserver *server,const char *ip,u_short port,int flag)
{
	if (*ip=='/') {
#ifdef KSOCKET_UNIX	
		ksocket_unix_addr(ip,&server->un_addr);
#endif
	} else {
		if (!ksocket_getaddr(ip, port, 0, AI_NUMERICHOST, &server->addr)) {
			return false;
		}
	}
	SET(flag, KSOCKET_REUSEPORT);
	int selector_count = get_selector_count();
	int i;
	for (i = 0; i < selector_count; i++) {
		SOCKET sockfd = ksocket_listen(&server->addr, flag);
		if (ksocket_opened(sockfd)) {
			if (port == 0) {
				//update addr
				socklen_t addr_len = (socklen_t)ksocket_addr_len(&server->addr);
				getsockname(sockfd, (struct sockaddr *)&server->addr, &addr_len);
				//update port is set
				port = 1;
			}
			add_server_socket(server, sockfd);
#ifdef _WIN32
			break;
#endif
			continue;
		}
		break;
	}
	return server->ss != NULL;
}
bool kserver_open(kserver *server, const char *ip, uint16_t port, int flag, kgl_ssl_ctx *ssl_ctx) {
	kassert(server->ss == NULL);
	bool result = false;
#ifdef KSOCKET_SSL
	if (server->ssl && ssl_ctx == NULL) {
		return false;
	}
#endif
	//int flag = (ipv4 ? KSOCKET_ONLY_IPV4 : KSOCKET_ONLY_IPV6);
#ifdef ENABLE_TPROXY
	//if (TEST(server->flags, WORK_MODEL_TPROXY)) {
	//	flag |= KSOCKET_TPROXY;
	//}
#endif
	for (;;) {
		result = kserver_internal_open(server,ip,port,flag);
		if (result) {
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
	if (!result) {
		int err = errno;
		klog(KLOG_ERR, "cann't listen [%s:%d],error=[%d]\n", ip, port, err);
#ifdef KSOCKET_SSL
		if (ssl_ctx) {
			kgl_release_ssl_ctx(ssl_ctx);
		}
#endif
		return false;
	}
	klog(KLOG_NOTICE, "listen [%s:%d] success\n", ip, port);
#ifdef KSOCKET_SSL
	kserver_set_ssl_ctx(server, ssl_ctx);
#endif
	return true;
}
void kserver_bind(kserver *server, kserver_accept_callback accept_callback, kserver_close_callback close_callback, void *ctx)
{
	server->accept_callback = accept_callback;
	server->close_callback = close_callback;
	server->ctx = ctx;
}
bool kserver_accept(kserver *server)
{	
	kassert(!server->started);
	if (selector_manager_listen(server, handle_server_listen)) {
		server->started = 1;
		return true;
	}
	return false;
}

void kserver_free(kserver *server) {
	while (server->ss) {
		kserver_selectable *next = server->ss->next;
		kserver_selectable_free(server->ss);
		server->ss = next;
	}
	if (server->close_callback) {
		server->close_callback(server->ctx);
	}
	xfree(server);
}
void kserver_release(kserver *server)
{
	if (katom_dec((void *)&server->refs) == 0) {
		kserver_free(server);
	}
	return;
}
void kserver_close(kserver *server)
{
	server->closed = true;
	kserver_selectable *ss = server->ss;
	while (ss) {
		if (ksocket_opened(ss->st.fd)) {
			ksocket_shutdown(ss->st.fd, SHUT_RDWR);
			ksocket_close(ss->st.fd);
			ksocket_init(ss->st.fd);
		}
		ss = ss->next;
	}
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
	if (server->ssl && ssl_ctx == NULL) {
		//cann't set ssl_ctx to NULL
		return;
	}
	kserver_selectable *ss = server->ss;
	while (ss) {
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
		ss = ss->next;
	}
	if (ssl_ctx) {
		kgl_release_ssl_ctx(ssl_ctx);
	}
}
#endif

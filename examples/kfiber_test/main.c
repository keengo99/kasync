#include <stdio.h>
#include "kthread.h"
#include "kaddr.h"
#include "ksocket.h"
#include "kselector_manager.h"
#include "kfiber.h"
int chan_test(void *arg,int got);
void test_volatile();
typedef struct _krequest {
	kconnection *c;
	char buf[4096];
	int len;
} krequest;
void test_stack_address()
{
	int a = 0;
	int b = 0;
	printf("test_stack_address a=[%p],b=[%p]\n",&a,&b);
}
int kfiber_sleep_test(void *arg, int got)
{
	int a = 0;
	int b = 0;
	a += got;
	printf("kfiber val a=[%p],b=[%p]\n",&a,&b);
	test_stack_address();
	printf("kfiber sleep test,arg=[%p]\n", arg);
	b = kfiber_msleep(200);
	printf("msleep end\n");
	return b;
}
int kfiber_server_test(void *arg, int got)
{
	kconnection *cn = (kconnection *)arg;
	char buf[4096];
	kfiber_net_read(cn, buf, sizeof(buf) - 1);
	kfiber_net_write(cn, kgl_expand_string("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok"));
	kfiber_net_close(cn);
	return 0;
}
void kfiber_accept_callback(kconnection *c, void *ctx)
{
	//printf("accept new connection [%p]\n", c);
	kfiber_create(kfiber_server_test, c, 0, 0, NULL);
}
int buffer_write(KOPAQUE data, void *arg, WSABUF *buf, int bc)
{
	buf[0].iov_base = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok";
	buf[0].iov_len = sizeof("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok") - 1;
	return 1;
}
kev_result result_write(KOPAQUE data, void *arg, int got)
{
	krequest *rq = (krequest *)arg;
	kconnection_destroy(rq->c);
	free(rq);
	return kev_destroy;
}
kev_result result_read(KOPAQUE data, void *arg, int got)
{
	krequest *rq = (krequest *)arg;
	return selectable_write(&rq->c->st, result_write, buffer_write, rq);
}
int buffer_read(KOPAQUE data, void *arg, WSABUF *buf, int bc)
{
	krequest *rq = (krequest *)arg;
	buf[0].iov_base = rq->buf;
	buf[0].iov_len = sizeof(rq->buf) - 1;
	return 1;
}
void main_accept_callback(kconnection *c, void *ctx)
{
	krequest *rq = (krequest *)malloc(sizeof(krequest));
	rq->c = c;
	rq->len = 0;
	selectable_read(&c->st, result_read, buffer_read, rq);
}
int kfiber_file_test(void *arg, int got)
{
	printf("kfiber_file_test...\n");
	kfiber_file *fp = kfiber_file_open("test.txt", fileWrite, 0);
	if (fp == NULL) {
		printf("cann't open test file to write\n");
		return -1;
	}
	char *buf = aio_alloc_buffer(512);
	memcpy(buf,kgl_expand_string("test"));
	int ret = kfiber_file_write(fp, buf , 4);
	printf("write ret=[%d]\n", ret);
	kfiber_file_close(fp);
	fp = kfiber_file_open("test.txt", fileRead, 0);
	if (fp == NULL) {
		printf("cann't open test file to read\n");
		aio_free_buffer(buf);
		return -1;
	}
	kfiber_file_seek(fp, seekBegin, 1);
	ret = kfiber_file_read(fp, buf, 3);
	assert(memcmp(buf, "est", 3) == 0);
	printf("read ret=[%d] read buffer:\n", ret);
	if (ret>0) {
		fwrite(kfiber_file_adjust(fp,buf),1,ret,stdout);
		printf("\n");
	}
	kfiber_file_close(fp);
	aio_free_buffer(buf);
	printf("kfiber_file_test end...\n");
	return 0;
}
int kfiber_mutex_test(void *arg, int got)
{
	kfiber_mutex *mutex = (kfiber_mutex *)arg;
	kfiber_mutex_lock(mutex);
	printf("fiber [%p]\n", kfiber_self());
	kfiber_msleep(100);
	kfiber_mutex_unlock(mutex);
	return 0;
}
int kfiber_net_test(void *arg,int got)
{
	sockaddr_i addr;
	for (int i = 0;i < 2;i++) {
		printf("address test\n");		
		int ret = kfiber_net_getaddr("127.0.0.1", 80, &addr);
		assert(ret == 0);
	}
	uint16_t port = 80;
#ifdef KSOCKET_SSL
	SSL_CTX *ssl_ctx = kgl_ssl_ctx_new_client(NULL, NULL, NULL);
	port = 443;
#endif
	int ret = kfiber_net_getaddr("www.cdnbest.com", port, &addr);
	kconnection *cn = kconnection_new(&addr);
	ret = kfiber_net_connect(cn, NULL, 0);
	printf("connect ret=[%d]\n", ret);
#ifdef KSOCKET_SSL
	kconnection_ssl_connect(cn, ssl_ctx, "www.cdnbest.com");
	ret = kfiber_ssl_handshake(cn);
	printf("ssl_handshake ret=[%d]\n", ret);
#endif
	if (ret == 0) {
		ret = kfiber_net_write(cn, kgl_expand_string("GET /kangle.status HTTP/1.1\r\nHost: www.cdnbest.com\r\n\r\n"));
		printf("send result=[%d]\n", ret);
		char buf[4096];
		ret = kfiber_net_read(cn, buf, sizeof(buf)-1);
		printf("recv result=[%d]\n", ret);
		buf[ret] = '\0';
		printf("%s", buf);
	}
	kfiber_net_close(cn);
#ifdef KSOCKET_SSL
	SSL_CTX_free(ssl_ctx);
#endif
	return 0;
}
int main_fiber(void *arg,int got)
{
	int ret = 0;
	//kfiber_create(chan_test, NULL, 0, 0, NULL);
	printf("kfiber_mutex test...got=[%d]\n",got);
/*	
	kfiber_mutex *mutex = kfiber_mutex_init2(2);
	kfiber *f2[10];
	for (int i = 0;i < 10;i++) {
		kfiber_create(kfiber_mutex_test, mutex,0, 0, &f2[i]);
	}
	for (int i = 0;i < 10;i++) {
		kfiber_join(f2[i], &ret);
		printf("join i=[%d] ret=[%d]\n",i, ret);
		kfiber_release(f2[i]);
	}
	kfiber_mutex_destroy(mutex);
*/	
	
	kfiber *f = NULL;
	kfiber_create(kfiber_sleep_test, NULL,0, 0, &f);
	
	kfiber_join(f, &ret);
	printf("kfiber_sleep_test ret=[%d]\n", ret);
	//return 0;
	//kfiber_release(kfiber_create(kfiber_net_test, NULL, 0));
	kfiber_create(kfiber_file_test, NULL, 0, 0, NULL);
	return 0;
	kserver *server = kserver_init();
	if (!kserver_open(server, "0.0.0.0", 888, 0, NULL)) {
		printf("cann't listen to 888\n");
		return -1;
	}
	kserver_bind(server, kfiber_accept_callback, NULL, NULL);
	//kserver_bind(server, main_accept_callback, NULL, NULL);
	kserver_accept(server);
	kserver_release(server);

	server = kserver_init();
	if (!kserver_open(server, "0.0.0.0", 889, 0, NULL)) {
		printf("cann't listen to 888\n");
		return -1;
	}
	//kserver_bind(server, kfiber_accept_callback, NULL, NULL);
	kserver_bind(server, main_accept_callback, NULL, NULL);
	kserver_accept(server);
	kserver_release(server);
	return 0;
	//kfiber_release(kfiber_create(kfiber_net_server_test, NULL, 0));
}
kev_result main_timer_test(KOPAQUE data, void *arg, int got)
{
	assert(kfiber_msleep(100) != 0);
	return kev_ok;
}
void fiber_test(void *arg)
{
	assert(kfiber_msleep(100) != 0);
	selector_manager_add_timer(main_timer_test, NULL, 0, NULL);
	kfiber_create2(get_perfect_selector(),main_fiber, NULL,2, 0, NULL);
	//test_volatile();
}
int main()
{
	ksocket_startup();
	kthread_init();
#ifdef KSOCKET_SSL
	kssl_init(NULL, NULL, NULL);
#endif
	selector_manager_on_ready(fiber_test, NULL);
	selector_manager_init(1, true);
	kgl_addr_init();
	kfiber_init();
	selector_manager_start(NULL,false);
}

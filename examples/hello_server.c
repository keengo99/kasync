#include <string.h>
#include "kfeature.h"
#include "kconnection.h"
#include "kselectable.h"
#include "kserver.h"
#include "kmalloc.h"

typedef struct {
	kconnection *c;
	uint32_t serial;
	char buf[32];
	char *hot;
	int len;
} hello_request;

static kserver *m_hello_server = NULL;
static void result_hello(void *arg, int got);
void hello_request_destroy(hello_request *hr)
{
	kconnection_destroy(hr->c);
	xfree(hr);
}
static int buffer_hello(void *arg, LPWSABUF buf, int buf_count)
{
	hello_request *hr = (hello_request *)arg;
	buf[0].iov_base = hr->hot;
	buf[0].iov_len = hr->len - (int)(hr->hot - hr->buf);
	return 1;
}
static void hello_timer_write(void *arg, int got)
{
	hello_request *hr = (hello_request *)arg;
	selectable_write(&hr->c->st, result_hello, buffer_hello, hr);
}
static void hello_write(hello_request *hr)
{
	hr->len = sprintf(hr->buf, "%d\r\n", hr->serial++);
	hr->hot = hr->buf;
	kselector_add_timer(hr->c->st.selector, hello_timer_write, hr, 500, NULL);
}
static void result_hello(void *arg, int got)
{
	hello_request *hr = (hello_request *)arg;
	if (got <= 0) {
		hello_request_destroy(hr);
		return;
	}
	hr->hot += got;
	if (hr->hot - hr->buf == hr->len) {
		hello_write(hr);
		return;
	}
	selectable_write(&hr->c->st, result_hello, buffer_hello, hr);
}
static void my_accept_callback(kconnection *c, void *ctx)
{
	//printf("hello_server accept connection.\n");
	//printf("c->st->selector=[%p]\n", c->st.selector);
	hello_request *hr = (hello_request *)xmalloc(sizeof(hello_request));
	memset(hr, 0, sizeof(hello_request));
	hr->c = c;
	hr->serial = 1;
	hello_write(hr);
}

void hello_server()
{
	m_hello_server = kserver_init();
	if (!kserver_open(m_hello_server, "127.0.0.1", 9000, true)) {
		kserver_release(m_hello_server);
		return;
	}
	if (kserver_accept(m_hello_server, my_accept_callback, NULL, NULL)) {
		return;
	}
}
void hello_server_shutdown()
{
	kserver_close(m_hello_server);
}

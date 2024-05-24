#include "kserver.h"
#include "gtest/gtest.h"
#include "kfiber.h"
#include "ktest.h"
#include "kfeature.h"

static const char response_msg[] = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok";
static const char request_msg[] = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
KFIBER_FUNCTION(kfiber_server_test)
{
	kconnection *cn = (kconnection *)arg;
#ifdef KSOCKET_SSL
    if (cn->server->ssl_ctx) {
        assert(0 == kfiber_ssl_handshake(cn));
    }
#endif
	char buf[512];
    memset(buf,0,sizeof(buf));
    int len = sizeof(request_msg) - 1;
	kfiber_net_read_full(cn, buf, &len);    
    ASSERT_TRUE(len == 0);
   // printf("read msg = [%s]\n",buf);
    len = (int)strlen(response_msg);
	kfiber_net_write_full(cn, response_msg,&len);
    ASSERT_TRUE(len==0);
    //printf("write left len=[%d]\n",len);
    selectable_shutdown(&cn->st);
	kfiber_net_close(cn);	
}
KACCEPT_CALLBACK(accept_callback) {   
    kconnection* cn = (kconnection*)arg;
    assert(cn != NULL);
    assert(0==kfiber_create(kfiber_server_test, cn, 0, 0, NULL));
    return kev_ok;
}
void kfiber_client_fiber(kconnection* cn)
{
    int len = (int)strlen(request_msg);
    ASSERT_TRUE(kfiber_net_write_full(cn, request_msg, &len));
    char buf[512];
    len = sizeof(buf);
    kfiber_net_read_full(cn, buf, &len);
    int got = sizeof(buf) - len;
    ASSERT_TRUE(got == strlen(response_msg));
    ASSERT_TRUE(got == sizeof(response_msg) - 1);
    kfiber_net_close(cn);
}
void kfiber_client_connect(kserver *server)
{
    kconnection *cn = kconnection_new(&server->addr);
    ASSERT_TRUE(0==kfiber_net_connect(cn,NULL,0));
    kfiber_client_fiber(cn);
}
int kfiber_client_test(void *arg, int got)
{
    kserver *server = (kserver *)arg;
    for(int i=0;i<4;i++) {
        kfiber_client_connect(server);
    }
    return 0;
}
TEST(socket, server_open_close) {
   //   GTEST_SKIP();
    kserver* server = kserver_init();  
    ASSERT_TRUE(kserver_bind(server, "127.0.0.1", 0, NULL));//ipv4
    ASSERT_TRUE(kserver_open(server, 0, accept_callback));
     assert(server->refs == 2);
    // printf("open 8888 port success.\n");
    kfiber_msleep(100);
//    printf("shutdown server now...\n");
    kserver_shutdown(server);
    //printf("server->refs = [%d]\n",server->refs);
    kfiber_msleep(100);
    assert(server->refs == 1);
    kserver_release(server);
}
TEST(socket, server_open) {
    //GTEST_SKIP();
    kserver* server = kserver_init();  
    ASSERT_TRUE(kserver_bind(server, "127.0.0.1", 0, NULL));//ipv4
    ASSERT_TRUE(kserver_open(server, 0, accept_callback));
    //printf("server refs=[%d]\n",server->refs);
    kfiber_msleep(100);
    ASSERT_TRUE(0 == kfiber_client_test(server, 0));
    //printf("server refs=[%d] now shutdown..\n",server->refs);
    assert(server->refs == 2);
 
    kserver_shutdown(server);
    //printf("server->refs = [%d]\n",server->refs);
    kfiber_msleep(100);
    //printf("server->refs = [%d]\n", server->refs);
    assert(server->refs == 1);
    kserver_release(server);
}



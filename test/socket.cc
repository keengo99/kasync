#include "kserver.h"
#include "gtest/gtest.h"
#include "kfiber.h"

static const char response_msg[] = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok";
static const char request_msg[] = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
int kfiber_server_test(void *arg, int got)
{
	kconnection *cn = (kconnection *)arg;
	char buf[512];
    memset(buf,0,sizeof(buf));
    int len = sizeof(request_msg) - 1;
	kfiber_net_read_full(cn, buf, &len);
    
    assert(len==0);
   // printf("read msg = [%s]\n",buf);
    len = strlen(response_msg);
	kfiber_net_write_full(cn, response_msg,&len);
    assert(len==0);
    //printf("write left len=[%d]\n",len);
    selectable_shutdown(&cn->st);
	kfiber_net_close(cn);
    
	return 0;
}
static void accept_callback(kconnection *c,void *ctx)
{   
    assert(0==kfiber_create(kfiber_server_test, c, 0, 0, NULL));
}
void kfiber_client_connect(kserver *server)
{
    kconnection *cn = kconnection_new(&server->addr);
    assert(0==kfiber_net_connect(cn,NULL,0));  
    int len = strlen(request_msg);
    assert(kfiber_net_write_full(cn,request_msg,&len));
    char buf[512];
    len = sizeof(buf);
    kfiber_net_read_full(cn,buf,&len);
    int got = sizeof(buf) - len;
    assert(got==strlen(response_msg));
    assert(got==sizeof(response_msg)-1);
    kfiber_net_close(cn);
}
int kfiber_client_test(void *arg, int got)
{
    kserver *server = (kserver *)arg;
    for(int i=0;i<100;i++) {
        kfiber_client_connect(server);
    }
    kserver_release(server);
}
void close_callback(void *ctx)
{

}
TEST(socket, server_open) {    
    kserver* server = kserver_init();
    kserver_bind(server,accept_callback,close_callback,NULL);
    ASSERT_TRUE(kserver_open(server, "127.0.0.1", 0, 0, NULL));//ipv4
    ASSERT_TRUE(kserver_accept(server));
    assert(0==kfiber_create(kfiber_client_test, server, 0, 0, NULL));
}

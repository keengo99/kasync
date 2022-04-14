#include "kserver.h"
#include "gtest/gtest.h"
#include "kfiber.h"
#include "ktest.h"
KFIBER_FUNCTION(server_fiber) {
    kserver_selectable* ss = (kserver_selectable*)arg;
    kconnection* c = NULL;
    for (int i = 0; i < 2;i++) {
        ASSERT_TRUE(0 == kfiber_net_accept(ss, &c));
        ASSERT_TRUE(c != NULL);
        kfiber_server_test(c, 0);
    }
    kserver_selectable_destroy(ss);
}
TEST(socket, server_selectable) {
    GTEST_SKIP();
    kserver* server = kserver_init();
    ASSERT_TRUE(kserver_bind(server, "::1", 0,  NULL));//ipv6
    //kserver_selectable* ss = kserver_listen(server, 0, accept_callback, NULL);
    kserver_selectable* ss = NULL;
    ASSERT_TRUE(0==kfiber_net_listen(server, 0,&ss));

    ASSERT_TRUE(ss != NULL);
    ASSERT_TRUE(0==kfiber_create(server_fiber,ss,0,0,NULL));
    
    for (int i = 0; i < 2; i++) {
        kfiber_client_connect(server);
    }
    ASSERT_TRUE(server->refs == 1);
    kserver_release(server);
}

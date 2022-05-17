#include <stdio.h>
#include "kselector_manager.h"
#include "kfiber.h"

int connection_fiber(void *arg,int got)
{
    kconnection *cn = (kconnection *)arg;
    char ips[MAXIPLEN];
    ksocket_sockaddr_ip(&cn->addr,ips,sizeof(ips));
    printf("%s:%d comin\n",ips,ksocket_addr_port(&cn->addr));
    char buf[512];
    for(;;) {
        got = kfiber_net_read(cn,buf,sizeof(buf));
        if (got<=0) {
            break;
        }
        if (!kfiber_net_write_full(cn,buf,&got)) {
            break;
        }
    }
    kfiber_net_close(cn);
    return 0;
}
int main_fiber(void *arg,int argc)
{
    kserver* server = kserver_init();
    kserver_bind(server, "127.0.0.1", 0,  NULL);//ipv6
    kserver_selectable* ss = NULL;
    kfiber_net_listen(server, 0,&ss);
    printf("success listen 127.0.0.1:%d\n",ksocket_addr_port(&server->addr));
    for (;;) {
        kconnection* c = NULL;
        int ret = kfiber_net_accept(ss, &c);
        if (ret!=0) {
            break;
        }
        kfiber_create(connection_fiber,c,0,0,NULL);
    }
    kserver_selectable_destroy(ss);
    kserver_release(server);
}
int main(int argc,char **argv)
{
    kasync_main(main_fiber,NULL,0);
}
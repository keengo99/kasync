#ifndef KUDP_H_9fff9
#define KUDP_H_9fff9
#include "kfeature.h"
#include "ksocket.h"
#include "kselectable.h"
#include "kconnection.h"
#if defined(LINUX) || defined(_WIN32)
# define KUDP_EXTEND_SIZE sizeof(struct in_pktinfo)
#else
# define KUDP_EXTEND_SIZE sizeof(struct in_addr)
#endif
KBEGIN_DECLS
struct kudp_extend_s {
    union
    {
        char pktinfo[CMSG_SPACE(KUDP_EXTEND_SIZE)];
        char pkt6info[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    };
#ifdef _WIN32
    WSAMSG msg;
#endif
};
kconnection* kudp_new2(int flags,kselector *st);
INLINE kconnection* kudp_new(int flags)
{
    return kudp_new2(flags, kgl_get_tls_selector());
}
int kudp_get_recvaddr(kconnection *uc, struct sockaddr *addr);
bool kudp_bind(kconnection* uc, const sockaddr_i* addr);
bool kudp_add_multicast(kconnection* uc, const char *group);
bool kudp_send_to(kconnection* uc, const sockaddr_i* dst, const char* package, int package_len);
int kudp_send(kconnection* uc, const struct sockaddr* peer_addr, socklen_t peer_addr_len, const char* package, int package_len);
KEND_DECLS
#endif


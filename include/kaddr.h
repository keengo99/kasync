#ifndef KDNS_H_LSJ1JJJD
#define KDNS_H_LSJ1JJJD
#include "kfeature.h"
#include "kselector.h"
#include "ksocket.h"
#include "katom.h"
KBEGIN_DECLS
typedef enum  {
	kgl_addr_ip,
	kgl_addr_cname
} kgl_addr_type;

kev_result kgl_find_addr(const char *hostname, kgl_addr_type addr_type, kgl_addr_call_back cb, void *arg, kselector *selector);
kgl_addr *kgl_find_cache_addr(const char *hostname, kgl_addr_type addr_type);
inline bool kgl_addr_build(struct addrinfo *addr, uint16_t port, sockaddr_i *sockaddr) {
	ksocket_addrinfo_sockaddr(addr, port, sockaddr);
	return true;
}
kgl_addr* kgl_addr_new(struct addrinfo* ai);
void kgl_addr_refs(kgl_addr* addr);
void kgl_addr_release(kgl_addr *addr);
void kgl_addr_init();
void kgl_flush_addr_cache(time_t nowTime);
int kgl_get_addr_cache_count();
KEND_DECLS
#endif


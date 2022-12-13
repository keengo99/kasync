#ifndef _WIN32
#include <arpa/inet.h>
#endif
#include <errno.h>
#include "kudp.h"
#include "kmalloc.h"
#include "kfile.h"
#ifdef _WIN32
#define CMSG_DATA(msg) (msg+1)
#endif

kconnection* kconnection_internal_new();
int kconnection_buffer_addr(KOPAQUE data, void* arg, WSABUF *buffer, int bc);


bool kudp_add_multicast(kconnection* uc, const char* group)
{
	struct ip_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_multiaddr.s_addr = inet_addr(group);
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	if (setsockopt(uc->st.fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq)) < 0) {
		return false;
	}
	return true;
}
struct in_pktinfo *kudp_pktinfo(kconnection* uc)
{
	if (!KBIT_TEST(uc->st.st_flags,STF_UDP) || uc->udp == NULL) {
		return NULL;
	}
	struct cmsghdr *msg = (struct cmsghdr *)(uc->udp->pktinfo);
	if (msg->cmsg_level==IPPROTO_IP && msg->cmsg_type==IP_PKTINFO) {
		return (struct in_pktinfo *)CMSG_DATA(msg);
	}
	return NULL;
}
bool kudp_bind(kconnection*uc, const sockaddr_i* addr)
{
	if (bind(uc->st.fd, (struct sockaddr*)addr, ksocket_addr_len(addr)) < 0) {
		return false;
	}
	return true;
}
kconnection* kudp_new2(int flags, kselector* st)
{
	int n = 1;
	int domain = PF_INET;
	if (KBIT_TEST(flags, KSOCKET_ONLY_IPV6)) {
		domain = PF_INET6;
	}
	kconnection* uc = kconnection_internal_new();
	KBIT_SET(uc->st.st_flags, STF_UDP);
	if ((uc->st.fd = ksocket_new_udp(domain,flags)) == INVALID_SOCKET) {
		kconnection_destroy(uc);
		return NULL;
	}
	if (KBIT_TEST(flags, KSOCKET_IP_PKTINFO)) {
		setsockopt(uc->st.fd, IPPROTO_IP, IP_PKTINFO, (const char*)&n, sizeof(int));
		uc->udp = xmemory_new(kudp_extend);
	}
#ifndef KGL_IOCP
	KBIT_SET(uc->st.st_flags,STF_RREADY|STF_WREADY);
#endif
	selectable_bind(&uc->st, st);
	return uc;
}
bool kudp_send_to(kconnection*uc,const sockaddr_i *dst,const char *package, int package_len)
{
	if (sendto(uc->st.fd, package, package_len, 0, (struct sockaddr *)dst, ksocket_addr_len(dst)) < 0) {
		return false;
	}
	return true;
}
int kudp_send(kconnection* uc, const struct sockaddr* peer_addr, socklen_t peer_addr_len, const char* package, int package_len)
{
	return sendto(uc->st.fd, package, package_len, 0, peer_addr, peer_addr_len);
}
kev_result kudp_recv_from(kconnection*uc, result_callback result, buffer_callback buffer, void* arg)
{
	if (!kgl_selector_module.recvmsg(uc->st.selector, &uc->st, result, buffer, arg)) {
		return result(uc->st.data, arg, -1);
	}
	return kev_ok;
}

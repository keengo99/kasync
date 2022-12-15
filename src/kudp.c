#include "kudp.h"
#include <errno.h>
#ifndef _WIN32
#include <arpa/inet.h>
#endif
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
int kudp_get_recvaddr(kconnection *uc, struct sockaddr *addr)
{
	if (!KBIT_TEST(uc->st.st_flags,STF_UDP) || uc->udp == NULL) {
		return -1;
	}
	struct cmsghdr *msg = (struct cmsghdr *)(uc->udp->pktinfo);
	if (addr->sa_family==PF_INET) {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
#ifdef IP_SENDSRCADDR
		if (msg->cmsg_level==IPPROTO_IP && msg->cmsg_type==IP_SENDSRCADDR) {
#else
		if (msg->cmsg_level==IPPROTO_IP && msg->cmsg_type==IP_PKTINFO) {
#endif
			memcpy(&addr4->sin_addr,CMSG_DATA(msg),sizeof(addr4->sin_addr));
			return 0;
		}
	} else {
		if (msg->cmsg_level==IPPROTO_IPV6 && msg->cmsg_type==IPV6_PKTINFO) {
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
			memcpy(&addr6->sin6_addr,CMSG_DATA(msg),sizeof(addr6->sin6_addr));
			return 0;
		}
	}
	return -1;
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
#ifdef IP_SENDSRCADDR
		setsockopt(uc->st.fd, IPPROTO_IP, IP_SENDSRCADDR, (const char*)&n, sizeof(int));
#else
		setsockopt(uc->st.fd, IPPROTO_IP, IP_PKTINFO, (const char*)&n, sizeof(int));
#endif
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
	KASYNC_IO_RESULT got;
retry:
	got = kgl_selector_module.recvmsg(uc->st.selector, &uc->st, result, buffer, arg);
	switch (got) {
		case KASYNC_IO_PENDING:
			return kev_ok;
		case KASYNC_IO_ERR_BUFFER:
			goto retry;
		case KASYNC_IO_ERR_SYS:
		default:
			kgl_selector_module.next(uc->st.selector, uc->st.data, result, arg, got);
			return kev_ok;
	}
}

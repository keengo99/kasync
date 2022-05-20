#ifndef _WIN32
#include <arpa/inet.h>
#endif
#include <errno.h>
#include "kudp.h"
#include "kmalloc.h"
#include "kfile.h"

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
struct in_pktinfo *kudp_pktinfo(kconnection *uc)
{
	if (uc->udp==NULL) {
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
kconnection *kudp_new(int flags)
{
	int n = 1;
	int type = SOCK_DGRAM;
	int domain = PF_INET;
	if (KBIT_TEST(flags, KSOCKET_ONLY_IPV6)) {
		domain = PF_INET6;
	}
#ifdef SOCK_CLOEXEC
	KBIT_SET(type, SOCK_CLOEXEC);
#ifndef KGL_IOCP
	KBIT_SET(type, SOCK_NONBLOCK);
#endif
#endif
	kconnection* uc = kconnection_internal_new();
	KBIT_SET(uc->st.st_flags,STF_UDP);
	if ((uc->st.fd = socket(domain, type, 0)) == INVALID_SOCKET) {
		//printf("socket failed errno=[%d],type=[%d]\n",errno,type);
		kconnection_destroy(uc);
		return NULL;
	}
#ifndef SOCK_CLOEXEC
	kfile_close_on_exec((FILE_HANDLE)uc->st.fd, true);
#endif
#ifdef SO_REUSEPORT
	if (KBIT_TEST(flags, KSOCKET_REUSEPORT)) {
		setsockopt(uc->st.fd, SOL_SOCKET, SO_REUSEPORT, (const char*)&n, sizeof(int));
	}
#endif
#ifdef IPV6_V6ONLY
	if (KBIT_TEST(flags, KSOCKET_ONLY_IPV6)) {
		setsockopt(uc->st.fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&n, sizeof(int));
	}
#endif
	if (KBIT_TEST(flags, KSOCKET_IP_PKTINFO)) {
		setsockopt(uc->st.fd, IPPROTO_IP, IP_PKTINFO, (const char*)&n, sizeof(int));
		uc->udp = xmemory_new(kudp_extend);
		memset(uc->udp,0,sizeof(kudp_extend));
	}
#ifndef KGL_IOCP
	//KBIT_SET(uc->st.st_flags,STF_RREADY|STF_WREADY);
#endif
	selectable_bind(&uc->st, kgl_get_tls_selector());
	return uc;
}
bool kudp_send_to(kconnection*uc,const sockaddr_i *dst,const char *package, int package_len)
{
	if (sendto(uc->st.fd, package, package_len, 0, (struct sockaddr *)dst, ksocket_addr_len(dst)) < 0) {
		return false;
	}
	return true;
}
kev_result kudp_recv_from(kconnection*uc, result_callback result, buffer_callback buffer, void* arg)
{
	if (!kgl_selector_module.recvfrom(uc->st.selector, &uc->st, result, buffer, arg)) {
		return result(uc->st.data, arg, -1);
	}
	return kev_ok;
}

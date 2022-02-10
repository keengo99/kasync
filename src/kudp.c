#include "kudp.h"
#include "kmalloc.h"

kudp_client *kudp_new_client(const sockaddr_i *src)
{
	SOCKET sockfd = socket(src->v4.sin_family, SOCK_DGRAM, 0);
	if (!ksocket_opened(sockfd)) {
		return NULL;
	}
	if (bind(sockfd, (struct sockaddr *)src, ksocket_addr_len(src)) < 0) {
		ksocket_close(sockfd);
		return NULL;
	}
	kudp_client *uc = xmemory_new(kudp_client);
	memset(uc, 0, sizeof(kudp_client));
	uc->st.fd = sockfd;
	return uc;
}
void kudp_free_client(kudp_client *uc)
{
	selectable_clean(&uc->st);
	xfree(uc);
}
bool kudp_send(kudp_client *uc,const sockaddr_i *dst,const char *package, int package_len)
{
	if (sendto(uc->st.fd, package, package_len, 0, (struct sockaddr *)dst, ksocket_addr_len(dst)) < 0) {
		return false;
	}
	return true;
}
kev_result kudp_recv_from(kudp_client *uc, void *arg, result_callback result, buffer_callback buffer, buffer_callback addr)
{
	if (!kgl_selector_module.recvfrom(uc->st.selector, &uc->st, result, buffer, addr, arg)) {
		return result(uc->st.data, arg, -1);
	}
	return kev_ok;
}

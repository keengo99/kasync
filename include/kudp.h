#ifndef KUDP_H_9fff9
#define KUDP_H_9fff9
#include "ksocket.h"
#include "kselectable.h"
#include "kconnection.h"

KBEGIN_DECLS
kconnection* kudp_new(int flags);
bool kudp_bind(kconnection* uc, const sockaddr_i* addr);
bool kudp_add_multicast(kconnection* uc, const char *group);
bool kudp_send_to(kconnection* uc, const sockaddr_i* dst, const char* package, int package_len);
kev_result kudp_recv_from(kconnection* uc, result_callback result, buffer_callback buffer, void* arg);
KEND_DECLS
#endif


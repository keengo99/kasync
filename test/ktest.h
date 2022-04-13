#ifndef KASYNC_TEST_H
#define KASYNC_TEST_H
#include "gtest/gtest.h"
#include "kserver.h"

#define KFIBER_FUNCTION_DECLEAR(fiber_name) \
int fiber_name(void *arg,int got)

#define KFIBER_FUNCTION(fiber_name) \
void void_##fiber_name##(void *arg,int got);\
int  fiber_name## (void *arg, int got) {\
	void_##fiber_name##(arg, got);\
	return 0;\
}\
void void_##fiber_name##(void *arg,int got)

KFIBER_FUNCTION_DECLEAR(kfiber_server_test);
void kfiber_client_connect(kserver* server);
KACCEPT_CALLBACK_DECLEAR(accept_callback);
void kfiber_client_fiber(kconnection* cn);
#endif


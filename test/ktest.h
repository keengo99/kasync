#ifndef KASYNC_TEST_H
#define KASYNC_TEST_H
#include "gtest/gtest.h"
#define KFIBER_FUNCTION(fiber_name) \
void void_##fiber_name##(void *arg,int got);\
int  fiber_name## (void *arg, int got) {\
	void_##fiber_name##(arg, got);\
	return 0;\
}\
void void_##fiber_name##(void *arg,int got)
#endif


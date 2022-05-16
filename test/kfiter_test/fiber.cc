#include "kfiber.h"
#include "ksocket.h"
#include "kasync_file.h"
#include "kselector_manager.h"
#include "gtest/gtest.h"

int kfiber_file_test(void* arg, int got)
{
	printf("kfiber_file_test...\n");
	kfiber_file* fp = kfiber_file_open("test.txt", fileWrite, 0);
	if (fp == NULL) {
		printf("cann't open test file to write\n");
		return -1;
	}
	char* buf = (char *)aio_alloc_buffer(512);
	memcpy(buf, kgl_expand_string("test"));
	int ret = kfiber_file_write(fp, buf, 4);
	assert(ret == 4);
	kfiber_file_close(fp);
	fp = kfiber_file_open("test.txt", fileRead, 0);
	if (fp == NULL) {
		printf("cann't open test file to read\n");
		aio_free_buffer(buf);
		return -1;
	}
	kfiber_file_seek(fp, seekBegin, 1);
	ret = kfiber_file_read(fp, buf, 3);
	if (ret > 0) {
		assert(memcmp(kfiber_file_adjust(fp, buf), "est",3) == 0);
	}
	kfiber_file_close(fp);
	aio_free_buffer(buf);
	printf("kfiber_file_test end...\n");
	return 3;
}
int kfiber_sleep_test(void* arg, int got)
{
	kfiber_msleep(100);
	printf("msleep success2.\n");
	return 3;
}
int main_fiber_test(void* arg, int got)
{
	assert(got == 2);
	printf("main_fiber_test\n");
	kfiber* f = NULL;
	int ret = 0;
	kfiber_create(kfiber_sleep_test, NULL, 0, 0, &f);
	kfiber_join(f, &ret);
	assert(ret == 3);
	printf("msleep success.\n");
	ret = 0;
	kfiber_create(kfiber_file_test, NULL, 0, 0, &f);
	kfiber_join(f, &ret);
	assert(ret == 3);
	return 3;
}
TEST(fiber, get_addr) {
	//GTEST_SKIP();
	kgl_addr* ai = NULL;
	kfiber_net_getaddr("www.qq.com", &ai);
	char ips[MAXIPLEN];
	ksocket_sockaddr_ip((sockaddr_i*)ai->addr->ai_addr, ips, sizeof(ips));
	kgl_addr_release(ai);
	printf("resolv dns www.qq.com ips=[%s]\n", ips);
}
TEST(fiber, file_test) {
	//GTEST_SKIP();
	kfiber* fiber = NULL;
	ASSERT_EQ(kfiber_create2(get_perfect_selector(), main_fiber_test, NULL, 2, 0, &fiber), 0);
	int ret = 0;
	ASSERT_TRUE(0 == kfiber_join(fiber, &ret));
	ASSERT_TRUE(ret == 3);
}

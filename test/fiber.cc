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
	return 3;
}
int main_fiber_test(void* arg, int got)
{
	assert(got == 2);
	kfiber* f = NULL;
	int ret = 0;
	kfiber_create(kfiber_sleep_test, NULL, 0, 0, &f);
	kfiber_join(f, &ret);
	assert(ret == 3);

	ret = 0;
	kfiber_create(kfiber_file_test, NULL, 0, 0, &f);
	kfiber_join(f, &ret);
	assert(ret == 3);
	return 3;
}
kev_result fiber_check_result(KOPAQUE data, void* arg, int got)
{
	assert(got == 3);
	return kev_ok;
}
TEST(fiber, file_test) {
	kfiber* fiber = NULL;
	ASSERT_EQ(kfiber_create2(get_perfect_selector(), main_fiber_test, NULL, 2, 0, &fiber), 0);
	//ASSERT_EQ(kfiber_create(main_fiber_test, NULL, 2, 0, &fiber), 0);
	kfiber_join2(fiber, NULL, fiber_check_result,NULL);
}

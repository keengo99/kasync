#include <stdio.h>
#include "kfeature.h"
#include "kselector_manager.h"
#include "kfiber.h"
#include "gtest/gtest.h"
TEST(main,system) {
	printf("event=[%s]\n",selector_manager_event_name());
}
kev_result main_test(KOPAQUE data, void* arg,int got)
{
	RUN_ALL_TESTS();
	return kev_ok;
}
int main(int argc, char** argv)
{
	testing::InitGoogleTest();
	kasync_init();
	kssl_init2();
	kfiber_init();
	selector_manager_init(1, true);
	selector_manager_on_ready(main_test, NULL);
	selector_manager_set_timeout(2,2);
	selector_manager_start(NULL, false);
	return 0;
}

#include <stdio.h>
#include "kfeature.h"
#include "kselector_manager.h"
#include "kfiber.h"
#include "kaddr.h"
#include "gtest/gtest.h"
TEST(main,system) {
	printf("event=[%s]\n",selector_manager_event_name());
}
int main_test(void* arg,int got)
{
	RUN_ALL_TESTS();
	return 0;
}
int main(int argc, char** argv)
{
	testing::InitGoogleTest(&argc,argv);
	kasync_init();
	kssl_init2();
	kgl_addr_init();
	selector_manager_init(1, true);
	//selector_manager_on_ready(main_test, NULL);
	selector_manager_set_timeout(2,2);
	kfiber_create2(get_perfect_selector(), main_test, NULL, 0, 0, NULL);
	selector_manager_start(NULL, false);
	return 0;
}

#include "kthread.h"
struct flags {
	int status;
};
int status;
KTHREAD_FUNCTION test_a(void *arg)
{
	struct flags *f = (struct flags *)arg;
	status = 0;
	while (status == 0) {
		printf("status is 0\n");
		//Sleep(100);
		sleep(1);
	}
	printf("test_a is end\n");
	KTHREAD_RETURN;
}

void test_volatile()
{
	printf("test_volatile\n");
	struct flags f;
	f.status = 0;
	//status = 0;
	kthread_start(test_a, &f);
	sleep(1);
	printf("now set status to 1\n");
	status = 1;
	//f.status = 1;
	sleep(2);
	return;
}

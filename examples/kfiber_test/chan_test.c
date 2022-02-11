#include "kfiber.h"
int chan_recv(void *arg,int got)
{
	printf("chan recv got=[%d]\n", got);
	int sum = 0;
	kfiber_chan *ch = (kfiber_chan *)arg;
	for (;;) {
		void *data;
		int ret = kfiber_chan_recv(ch,&data);
		if (ret <= 0) {
			return sum;
		}
		sum += (int)data;
		printf("chan recved=[%d]\n", (int)data);
	}
	return sum;
}
int chan_test(void *arg,int got)
{
	printf("chan test...\n");
	kfiber_chan *ch = kfiber_chan_create(2);
	kfiber *fiber;
	kfiber_create(chan_recv, ch, 1, 0, &fiber);
	for (int i = 1;i <= 100;i++) {
		printf("send chan result=[%d]\n", kfiber_chan_send(ch, (void *)i, 1));
	}
	kfiber_chan_shutdown(ch);
	int retval;
	kfiber_join(fiber, &retval);
	kfiber_chan_close(ch);
	assert(retval == 5050);
	//printf("retval=[%d]\n", retval);
	return 0;
}
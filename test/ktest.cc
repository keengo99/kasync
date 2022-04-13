#include "ktest.h"
#include "kfiber.h"

KFIBER_FUNCTION(pipe_data) {
	kconnection* a = (kconnection*)arg;
	kconnection* b = (kconnection*)a->st.data;
	char buf[512];
	int len;
	for (;;) {
		len = kfiber_net_read(a, buf, sizeof(buf));
		if (len <= 0) {
			break;
		}
		ASSERT_TRUE(kfiber_net_write_full(b, buf, &len));
	}
	kfiber_net_close(a);
}
void pipe_connection(kconnection* a, kconnection* b)
{
	a->st.data = b;
	b->st.data = a;
	kfiber_create(pipe_data, a, 0, 0, NULL);
	kfiber_create(pipe_data, b, 0, 0, NULL);
}

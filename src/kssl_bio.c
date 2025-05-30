#include <errno.h>
#include "kssl_bio.h"
#include "kbuf.h"
#include "kselectable.h"
#include "klog.h"
#ifdef ENABLE_KSSL_BIO
static int kgl_bio_write(BIO *h, const char *buf, int num)
{
	if (buf == NULL) {
		klog(KLOG_ERR, "ssl_bio write data is NULL,len=[%d]\n", num);
		return -1;
	}
	//BIO_get_app_data()
	krw_buffer *bb = (krw_buffer *)BIO_get_data(h);
	krw_write_str(bb, buf, (int)num);
	return num;
}
static int kgl_bio_read(BIO *h, char *buf, int size)
{
	krw_buffer *bb = (krw_buffer *)BIO_get_data(h);
	if (buf==NULL) {
		klog(KLOG_ERR,"ssl_bio read buf is NULL[%d]\n");
		return -1;
	}
	int got = krw_read(bb, buf, (int)size);
	//printf("bio_read bio=[%p] size=[%d] got=[%d] buf_len=[%d] shutdown=[%d]\n", h, size,got,bb->buf.getLen(),h->shutdown);
	BIO_clear_retry_flags(h);
	if (got <= 0) {
		if (!BIO_get_shutdown(h)) {
			BIO_set_retry_read(h);
			errno = EAGAIN;
			//_set_errno(EAGAIN);
			return -1;
		}
	}
	return got;
}
static int kgl_bio_puts(BIO *h, const char *str)
{
	return kgl_bio_write(h, str, (int)strlen(str));
}
static long kgl_bio_ctrl(BIO *h, int cmd, long arg1, void *arg2)
{
	krw_buffer *bb = (krw_buffer *)BIO_get_data(h);
	//long ret;
	//printf("kgl_bio_ctrl cmd=[%d] arg1=[%d]\n", cmd, arg1);
	switch (cmd) {
	case BIO_CTRL_PENDING:
		return (long)bb->total_len;
	case BIO_CTRL_WPENDING:
		return 0;
	case BIO_CTRL_GET_CLOSE:
		return BIO_get_shutdown(h);
	case BIO_CTRL_SET_CLOSE:
		BIO_set_shutdown(h,(int)arg1);
		return 1;
	case BIO_CTRL_DUP:
	case BIO_CTRL_FLUSH:
		return 1;
	case BIO_CTRL_PUSH:
	case BIO_CTRL_POP:
	default:
		break;
	}
	return 0;
}
static int kgl_bio_new(BIO *bi)
{
	krw_buffer *bb = krw_buffer_new(16384);
	if (bb == NULL) {
		return 0;
	}
	BIO_set_shutdown(bi, 0);
	BIO_set_init(bi, 1);
	BIO_set_data(bi, bb);
	return 1;
}
static int kgl_bio_buf_free(BIO *a, int free_all)
{
	if (a == NULL || !BIO_get_init(a)) {
		return (0);
	}
	krw_buffer *bb = (krw_buffer *)BIO_get_data(a);
	if (bb != NULL) {
		krw_buffer_destroy(bb);
	}
	BIO_set_data(a, NULL);
	return (1);
}
static int kgl_bio_free(BIO *h)
{
	return kgl_bio_buf_free(h, 1);
}
static BIO_METHOD *kgl_method = NULL;
#if 0
static BIO_METHOD kgl_method = {
	BIO_TYPE_MEM,
	"kgl buffer",
	kgl_bio_write,
	kgl_bio_read,
	kgl_bio_puts,
	NULL,
	kgl_bio_ctrl,
	kgl_bio_new,
	kgl_bio_free,
	NULL,
};
#endif
BIO_METHOD *BIO_kgl_method()
{
	return kgl_method;
}
void kgl_bio_init_method()
{
	if (kgl_method != NULL) {
		return;
	}
	kgl_method = BIO_meth_new(BIO_TYPE_MEM, "kgl_bio");
	BIO_meth_set_write(kgl_method, kgl_bio_write);
	BIO_meth_set_read(kgl_method, kgl_bio_read);
	BIO_meth_set_puts(kgl_method, kgl_bio_puts);
	BIO_meth_set_ctrl(kgl_method, kgl_bio_ctrl);
	BIO_meth_set_create(kgl_method, kgl_bio_new);
	BIO_meth_set_destroy(kgl_method, kgl_bio_free);
}
void kgl_bio_clean_method() {
	if (kgl_method != NULL) {
		BIO_meth_free(kgl_method);
		kgl_method = NULL;
	}
}
kev_result result_ssl_bio_read(KOPAQUE data, void *arg, int got)
{
	kssl_bio_buffer* bio_buffer = (kssl_bio_buffer*)arg;
	kssl_bio* ssl_bio = bio_buffer->bio;
	if (got == ST_ERR_TIME_OUT) {
		assert(KBIT_TEST(ssl_bio->st->base.st_flags, STF_READ));
		return ssl_bio->result(data, ssl_bio->arg, got);
	}
	xfree(bio_buffer);
	krw_buffer* bb = (krw_buffer*)BIO_get_data(ssl_bio->bio);
	if (got <= 0) {
		BIO_set_shutdown(ssl_bio->bio,1);
	} else {
		krw_write_success(bb, got);
	}
	return selectable_event_read(ssl_bio->st, ssl_bio->result, ssl_bio->buffer, ssl_bio->arg);
}

kev_result result_ssl_bio_write(KOPAQUE data, void *arg, int got)
{
	kssl_bio_buffer* bio_buffer = (kssl_bio_buffer*)arg;
	kssl_bio* ssl_bio = bio_buffer->bio;
	krw_buffer *bb = (krw_buffer *)BIO_get_data(ssl_bio->bio);
	if (got <= 0) {
		xfree(bio_buffer);
		return ssl_bio->result(data, ssl_bio->arg, got);
	}	
	if (krw_read_success(bb, got)) {
		buffer_ssl_bio_write(bio_buffer);
		return kgl_selector_module.write(ssl_bio->st->base.selector, ssl_bio->st, result_ssl_bio_write, bio_buffer->buf, bio_buffer);
	}
	xfree(bio_buffer);
	return ssl_bio->result(data, ssl_bio->arg, ssl_bio->got);
}

#endif

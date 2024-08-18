#ifndef KSSL_BIO_H_99
#define KSSL_BIO_H_99
#include "kfeature.h"
#ifdef ENABLE_KSSL_BIO
#include "kselector.h"
#include "kbuf.h"
#include "openssl/bio.h"
KBEGIN_DECLS
typedef struct {
	BIO *bio;
	buffer_callback buffer;
	result_callback result;
	kselectable *st;
	void *arg;
	int got;
} kssl_bio;

#define KGL_MAX_IOVEC_COUNT 64
typedef struct {
	kssl_bio* bio;
	kgl_iovec buf[KGL_MAX_IOVEC_COUNT];
} kssl_bio_buffer;

void kgl_bio_init_method();
void kgl_bio_clean_method();
BIO_METHOD *BIO_kgl_method();
kev_result result_ssl_bio_read(KOPAQUE data, void *arg, int got);
kev_result result_ssl_bio_write(KOPAQUE data, void *arg, int got);
INLINE void  buffer_ssl_bio_read(kssl_bio_buffer* bio_buffer) {
	bio_buffer->buf[0].iov_base = (char*)&bio_buffer->buf[1];
	bio_buffer->buf[0].iov_len = 1;
	krw_buffer* bb = (krw_buffer*)BIO_get_data(bio_buffer->bio->bio);
	int len;
	bio_buffer->buf[1].iov_base = krw_get_write_buffer(bb, &len);
	bio_buffer->buf[1].iov_len = len;
}
INLINE void  buffer_ssl_bio_write(kssl_bio_buffer* bio_buffer) {
	krw_buffer* bb = (krw_buffer*)BIO_get_data(bio_buffer->bio->bio);
	bio_buffer->buf[0].iov_base = (char*)&bio_buffer->buf[1];
	bio_buffer->buf[0].iov_len = krw_get_read_buffers(bb, &bio_buffer->buf[1], KGL_MAX_IOVEC_COUNT - 1);
}
KEND_DECLS
#endif
#endif


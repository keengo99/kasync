#ifndef KBUFFER_H_99
#define KBUFFER_H_99
#include <stdlib.h>
#include "kfeature.h"
#include "kforwin32.h"
#include "kmalloc.h"
KBEGIN_DECLS


INLINE kbuf* new_pool_kbuf_align(kgl_pool_t* pool, int len)
{
	kbuf* b = (kbuf*)kgl_pnalloc(pool, sizeof(kbuf));
	b->used = len;
	b->flags = 0;
	b->data = (char*)kgl_pmemalign(pool, len, kgl_aio_align_size);
	return b;
}
INLINE kbuf *new_pool_kbuf(kgl_pool_t *pool, int len)
{
	kbuf *b = (kbuf *)kgl_pnalloc(pool, sizeof(kbuf));
	b->used = len;
	b->flags = 0;
	b->data = (char *)kgl_pnalloc(pool, len);
	return b;
}
INLINE kbuf * new_kbuf(int len)
{
	kbuf *b = (kbuf *)xmalloc(sizeof(kbuf));
	b->used = len;
	b->flags = 0;
	b->data = (char *)xmalloc(len);
	return b;
}

INLINE void free_kbuf(kbuf *buf)
{
	if (buf->data) {
		xfree(buf->data);
	}
	xfree(buf);
}
INLINE void destroy_kbuf(kbuf *buf)
{
	kbuf *next;
	while (buf) {
		next = buf->next;
		free_kbuf(buf);
		buf = next;
	}
}
typedef struct {
	kbuf *head;
	kbuf *write_hot_buf;
	char *read_hot;
	char *write_hot;
	int total_len;
	int chunk_size;
} krw_buffer;

#if 0
typedef struct {
	kbuf *head;
	char *read_hot;
	int total_len;
} kr_buffer;
#endif

typedef struct {
	char *buf;
	int buf_size;
	int used;
} ks_buffer;

INLINE void ks_buffer_init(ks_buffer* buf, int buf_size) {
	memset(buf, 0, sizeof(ks_buffer));
	buf->buf = (char*)xmalloc(buf_size);
	buf->buf_size = buf_size;
}
INLINE ks_buffer* ks_buffer_new(int chunk_size) {
	ks_buffer* b = (ks_buffer*)xmalloc(sizeof(ks_buffer));
	ks_buffer_init(b, chunk_size);
	return b;
}

INLINE void ks_buffer_clean(ks_buffer *buf)
{
	xfree(buf->buf);
}
INLINE void ks_write_success(ks_buffer *buf, int got) {
	buf->used += got;
}
INLINE void ks_buffer_destroy(ks_buffer *buf) {
	ks_buffer_clean(buf);
	xfree(buf);
}
bool ks_write_str(ks_buffer *buf, const char *str, int len);
void ks_write_int(ks_buffer *buf, int val);
void ks_write_int64(ks_buffer *buf, int64_t val);
INLINE char *ks_get_write_buffer(ks_buffer *buf, int *len) {
	kassert(buf->buf_size > 0);
	for (;;) {
		int left = buf->buf_size - buf->used;
		if (left <= 0) {
			int new_size = buf->buf_size * 2;
			new_size = kgl_align(new_size, 1024);
			buf->buf_size = new_size;
			char* n = (char*)xmalloc(buf->buf_size);
			kgl_memcpy(n, buf->buf, buf->used);
			xfree(buf->buf);
			buf->buf = n;
			continue;
		}
		*len = left;
		return buf->buf + buf->used;
	}
}
void ks_save_point(ks_buffer *buf, const char *hot);

INLINE void ks_buffer_switch_read(ks_buffer *buf)
{
	buf->buf_size = buf->used;
	buf->used = 0;
}
int ks_get_read_buffers(ks_buffer *buf, LPWSABUF buffer, int buffer_count);
int ks_get_write_buffers(ks_buffer *buf, LPWSABUF buffer, int buffer_count);
//return true if still have data to read
bool ks_read_success(ks_buffer *buf, int got);
char *ks_get_read_buffer(ks_buffer *buf, int *len);

krw_buffer *krw_buffer_new(int chunk_size);
void krw_buffer_clean(krw_buffer *rw_buffer);
void krw_buffer_destroy(krw_buffer *rw_buffer);
void krw_buffer_init(krw_buffer *rw_buffer, int chunk_size);
int krw_get_read_buffers(krw_buffer *rw_buffer,LPWSABUF buffer, int buffer_count);
char *krw_get_read_buffer(krw_buffer *rw_buffer,int *len);
int krw_read(krw_buffer *rw_buffer, char *buf, int len);

//return true if still have data to read
bool krw_read_success(krw_buffer *rw_buffer,int got);
char *krw_get_write_buffer(krw_buffer *rw_buffer, int *len);
void krw_write_success(krw_buffer *rw_buffer, int got);
void krw_write_str(krw_buffer *rw_buffer,const char *buf, int len);
void krw_write_int(krw_buffer *rw_buffer, int val);
void krw_write_int64(krw_buffer *rw_buffer, int64_t val);

void krw_append(krw_buffer *rw_buffer, kbuf *buf);
void krw_insert(krw_buffer *rw_buffer, kbuf *buf);
kbuf* kbuf_init_read(kbuf* head, int offset, kgl_pool_t* pool);
void debug_print_buff(kbuf* buf);
KEND_DECLS
#endif


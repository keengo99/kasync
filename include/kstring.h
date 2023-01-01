#ifndef KSTRING_H_99
#define KSTRING_H_99
#include <stdlib.h>
#include "kfeature.h"
#include "kforwin32.h"
#include "katom.h"
#include "kmalloc.h"

KBEGIN_DECLS
typedef struct {
	char *data;
	size_t len;
} kgl_str_t;

typedef struct {
	volatile int32_t refs;
	int  len;
	const char* data;
} kgl_refs_string;

#define kgl_string(str)     { (char *)str,sizeof(str) - 1 }
#define kgl_null_string     {  NULL,0 }
#define kgl_str_set(str, text) \
    (str)->len = sizeof(text) - 1; (str)->data = (char *) text
#define kgl_str_null(str)   (str)->len = 0; (str)->data = NULL


INLINE kgl_refs_string *convert_refs_string(char *str, int len)
{
	kgl_refs_string *s = xmemory_new(kgl_refs_string);
	s->refs = 1;
	s->data = str;
	s->len = len;
	return s;
}
INLINE kgl_refs_string *kstring_refs(kgl_refs_string *s)
{
	if (!s) {
		return NULL;
	}
	katom_inc((void *)&s->refs);
	return s;
}
INLINE void kstring_release(kgl_refs_string *s)
{
	if (!s) {
		return;
	}
	if (katom_dec((void *)&s->refs) == 0) {
		xfree((void *)s->data);
		xfree(s);
	}
}
INLINE kgl_refs_string* kstring_from(const char* str) {
	if (str && *str) {
		int len = (int)strlen(str);
		return convert_refs_string(kgl_strndup(str, len), len);
	}
	return NULL;
}
KEND_DECLS
#endif

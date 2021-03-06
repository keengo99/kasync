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
	kgl_str_t str;
	volatile int32_t refs;
} kgl_refs_string;

#define kgl_string(str)     { (char *)str,sizeof(str) - 1 }
#define kgl_null_string     {  NULL,0 }
#define kgl_str_set(str, text) \
    (str)->len = sizeof(text) - 1; (str)->data = (char *) text
#define kgl_str_null(str)   (str)->len = 0; (str)->data = NULL

INLINE int64_t string2int(const char *buf) {
#ifdef _WIN32
	return _atoi64(buf);
#else
	return atoll(buf);
#endif
}
INLINE kgl_refs_string *convert_refs_string(char *str, int len)
{
	kgl_refs_string *s = xmemory_new(kgl_refs_string);
	s->refs = 1;
	s->str.data = str;
	s->str.len = len;
	return s;
}
INLINE void refs_string(kgl_refs_string *s)
{
	katom_inc((void *)&s->refs);
}
INLINE void release_string(kgl_refs_string *s)
{
	if (katom_dec((void *)&s->refs) == 0) {
		xfree(s->str.data);
		xfree(s);
	}
}
KEND_DECLS
#endif

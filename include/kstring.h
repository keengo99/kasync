#ifndef KSTRING_H_99
#define KSTRING_H_99
#include <stdlib.h>
#include "kfeature.h"
#include "kforwin32.h"
#include "katom.h"
#include "kmalloc.h"

KBEGIN_DECLS
typedef kgl_ref_str_t kgl_refs_string;

#define kgl_string2(str)		{(char *)str, 1,sizeof(str)-1}
#define kgl_string(str)     { (char *)str,sizeof(str) - 1 }
#define kgl_null_string     {  NULL,0 }
#define kgl_str_set(str, text) \
    (str)->len = sizeof(text) - 1; (str)->data = (char *) text
#define kgl_str_null(str)   (str)->len = 0; (str)->data = NULL


INLINE kgl_ref_str_t* convert_refs_string(char* str, int len) {
	kgl_ref_str_t* s = xmemory_new(kgl_ref_str_t);
	s->ref = 1;
	s->data = str;
	s->len = len;
	return s;
}
INLINE kgl_ref_str_t* kstring_refs(kgl_ref_str_t* s) {
	if (!s) {
		return NULL;
	}
	katom_inc((void*)&s->ref);
	return s;
}
INLINE void kstring_release(kgl_ref_str_t* s) {
	if (!s) {
		return;
	}
	if (katom_dec((void*)&s->ref) == 0) {
		xfree((void*)s->data);
		xfree(s);
	}
}
INLINE kgl_ref_str_t* kstring_from(const char* str) {
	if (str && *str) {
		int len = (int)strlen(str);
		return convert_refs_string(kgl_strndup(str, len), len);
	}
	return NULL;
}
INLINE kgl_ref_str_t* kstring_from2(const char* str, size_t len) {
	if (len > 0) {
		return convert_refs_string(kgl_strndup(str, len), (int)len);
	}
	return NULL;
}
KEND_DECLS
#endif

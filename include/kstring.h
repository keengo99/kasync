#ifndef KSTRING_H_99
#define KSTRING_H_99
#include <stdlib.h>
#include <assert.h>
#include "kfeature.h"
#include "kforwin32.h"
#include "katom.h"
#include "kmalloc.h"

KBEGIN_DECLS
typedef kgl_ref_str_t kgl_refs_string;

#define kgl_string2(str,len) {(char *)str, len}
#define kgl_string(str)     { (char *)str,sizeof(str) - 1 }
#define kgl_null_string     {  NULL,0 }
#define kgl_str_set(str, text) \
    (str)->len = sizeof(text) - 1; (str)->data = (char *) text
#define kgl_str_null(str)   (str)->len = 0; (str)->data = NULL

INLINE size_t kgl_len_str_size(size_t len) {
	return sizeof(kgl_len_str_t) + len + 1;
}
INLINE kgl_ref_str_t* convert_refs_string(char* str, size_t len) {
	kgl_ref_str_t* s = xmemory_new(kgl_ref_str_t);
	s->ref = 1;
	s->data = str;
	s->len = (uint32_t)len;
	return s;
}
INLINE uint32_t kstring_get_ref(const kgl_ref_str_t* s) {
	return katom_get((void*)&s->ref);
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
	assert(katom_get((void*)&s->ref) < 0xfffffff);
	if (katom_dec((void*)&s->ref) == 0) {
		if (s->data) {
			xfree((void*)s->data);
		}
		xfree(s);
	}
}
INLINE kgl_ref_str_t* kstring_from(const char* str) {
	if (str) {
		size_t len = strlen(str);
		return convert_refs_string(kgl_strndup(str, len), len);
	}
	return NULL;
}
INLINE kgl_ref_str_t* kstring_from2(const char* str, size_t len) {
	return convert_refs_string(kgl_strndup(str, len), len);
}
#if 0
INLINE kgl_ref_str_t* kstring_clone(const kgl_ref_str_t* s) {
	if (s->data) {
		return kstring_from2(s->data, s->len);
	}
	return convert_refs_string(NULL, 0);
}
#endif
KEND_DECLS
#endif

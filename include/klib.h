#ifndef KLIB_H_99
#define KLIB_H_99
#include "kfeature.h"
KBEGIN_DECLS
void kgl_msleep(int msec);
INLINE bool kgl_is_absolute_path(const char* str) {
	if (*str == '/') {
		return true;
	}
#ifdef _WIN32
	if (*str == '\\') {
		return true;
	}
	if (*str && *(str + 1) == ':') {
		/* c:\dir */
		return true;
	}
#endif
	return false;
}
KEND_DECLS
#endif
#ifndef KLOG_H_23541234123413241234
#define KLOG_H_23541234123413241234
#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include "kfeature.h"
#define KLOG_ERR			1
#define KLOG_WARNING		2
#define KLOG_NOTICE			3
#define KLOG_INFO			4
#define KLOG_DEBUG			5
KBEGIN_DECLS
typedef void (*kgl_vklog_callback)(int level, const char* fmt, va_list ap);
extern kgl_vklog_callback kgl_vklog_callback_f;
INLINE void vklog(int level, const char* fmt, va_list ap) {
	if (kgl_vklog_callback_f) {
		kgl_vklog_callback_f(level, fmt, ap);
	} else {
		vprintf(fmt, ap);
	}
}
INLINE void klog(int level, const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vklog(level, fmt, ap);
	va_end(ap);
}
void klog_init(kgl_vklog_callback kgl_vklog);
void debug(const char *fmt, ...);
KEND_DECLS
#endif

#include <stdio.h> 
#ifndef _WIN32
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#endif
#include "klog.h"
kgl_vklog_callback kgl_vklog_callback_f = NULL;

void klog_init(kgl_vklog_callback kgl_vklog)
{
	kgl_vklog_callback_f = kgl_vklog;
}

void debug(const char *fmt, ...) {
#ifndef NDEBUG	
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
#endif
}

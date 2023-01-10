#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include "klib.h"
#include "kforwin32.h"
#include "kfile.h"
#include "kfiber.h"
void kgl_msleep(int msec) {
	kassert(kfiber_is_main());
#ifdef _WIN32
	Sleep(msec);
#else
	usleep(msec * 1000);
#endif
}

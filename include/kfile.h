#ifndef KFILE_H_99
#define KFILE_H_99
#include <sys/types.h>
#include <sys/stat.h>
#include "kfeature.h"
#include "kforwin32.h"
KBEGIN_DECLS
INLINE bool kfile_close_on_exec(FILE_HANDLE fd, bool close_on_exec)
{
#ifndef _WIN32
	//return fcntl(fd, F_SETFD, (closeExec ? FD_CLOEXEC : 0)) == 0;
#else
	return SetHandleInformation((HANDLE)fd, HANDLE_FLAG_INHERIT, (close_on_exec ? 0 : HANDLE_FLAG_INHERIT)) == 0;
#endif
	return true;
}
#ifdef _WIN32
INLINE int kfwrite(FILE_HANDLE h, const char *buf, int len)
{
	int ret = 0;
	if (WriteFile(h, (void *)buf, len, (LPDWORD)&ret, NULL)) {
		return ret;
	}
	return -1;
}
INLINE int kfread(FILE_HANDLE h, char *buf, int len)
{
	int ret = 0;
	if (ReadFile(h, (void *)buf, len, (LPDWORD)&ret, NULL)) {
		return ret;
	}
	return -1;
}
#define kfinit(h)              (h=INVALID_HANDLE_VALUE)
#define kflike(h)              (h!=INVALID_HANDLE_VALUE)
#define kfclose             CloseHandle
FILE_HANDLE kfopen_w(const wchar_t* path, fileModel model, int flag);
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#define kfclose                close
#define kfwrite                write
#define kfread                 read
#define kflike(h)              (h>=0)
#define kfinit(h)              (h=-1)
#endif
FILE_HANDLE kfopen(const char *path, fileModel model, int flag);
INLINE int64_t kfsize(FILE_HANDLE fp)
{
#ifdef _WIN32
	BY_HANDLE_FILE_INFORMATION info;
	if (GetFileInformationByHandle(fp, &info)) {
		ULARGE_INTEGER    lv_Large;
		lv_Large.LowPart = info.nFileSizeLow;
		lv_Large.HighPart = info.nFileSizeHigh;
		return lv_Large.QuadPart;
	}
	return 0;
#else
	struct stat buf;
	if (fstat(fp, &buf) == 0) {
		return buf.st_size;
	}
	return 0;
#endif
}
//update file modified time
INLINE bool kfutime(FILE_HANDLE h, time_t time)
{
#ifdef _WIN32
	LARGE_INTEGER t;
	t.QuadPart = time * 10000000 + 116444736000000000;
	return SetFileTime(h, NULL, NULL, (FILETIME *)&t);
#else
	struct timespec t[2];
	memset(&t, 0, sizeof(t));
	t[0].tv_sec = time;
	t[1].tv_sec = time;
	return futimens(h, t) == 0;
#endif
}
INLINE time_t kfile_last_modified(const char *file)
{
	struct _stati64 sbuf;
	int ret = lstat(file, &sbuf);
	if (ret != 0 || !S_ISREG(sbuf.st_mode)) {
		return 0;
	}
	return sbuf.st_mtime;
}
//get file modified time
INLINE time_t kftime(FILE_HANDLE fp)
{
#ifdef _WIN32
	BY_HANDLE_FILE_INFORMATION info;
	if (GetFileInformationByHandle(fp, &info)) {
		ULARGE_INTEGER    lv_Large;
		lv_Large.LowPart = info.ftCreationTime.dwLowDateTime;
		lv_Large.HighPart = info.ftCreationTime.dwHighDateTime;
		return (time_t)((lv_Large.QuadPart - 116444736000000000) / 10000000);
	}
	return 0;
#else
	struct stat buf;
	if (fstat(fp, &buf) == 0) {
		return buf.st_mtime;
	}
	return 0;
#endif
}
bool kfseek(FILE_HANDLE fp,int64_t len, seekPosion position);
INLINE bool kfread_all(FILE_HANDLE fp, char *buf, int length)
{
	while (length > 0) {
		int step_length = kfread(fp, buf, length);
		if (step_length <= 0) {
			return false;
		}
		buf += step_length;
		length -= step_length;
	}
	return true;
}
KEND_DECLS
#endif

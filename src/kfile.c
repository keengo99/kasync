#ifndef _WIN32
//#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#include <fcntl.h>
#endif
#include <stdio.h>
#include "kfile.h"
#ifdef _WIN32
FILE_HANDLE kfopen_w(const wchar_t* path, fileModel model, int flag) {
	int share_flag = FILE_SHARE_READ | FILE_SHARE_WRITE;
	int other_flag = 0;
	if (KBIT_TEST(flag, KFILE_TEMP_MODEL)) {
		share_flag = 0;
		other_flag = (FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE);
	}
#ifndef KF_ASYNC_WORKER
	if (KBIT_TEST(flag, KFILE_ASYNC)) {
		KBIT_SET(other_flag, FILE_FLAG_OVERLAPPED);
	}
#endif
	if (KBIT_TEST(flag, KFILE_DSYNC)) {
		KBIT_SET(other_flag, FILE_FLAG_WRITE_THROUGH);
	}
	if (KBIT_TEST(flag, KFILE_SEQUENTIAL)) {
		KBIT_SET(other_flag, FILE_FLAG_SEQUENTIAL_SCAN);
	}
	SECURITY_ATTRIBUTES sa;
	memset(&sa, 0, sizeof(sa));
	sa.bInheritHandle = FALSE;
	int flag1 = 0;
	int flag2 = OPEN_EXISTING;
	switch (model) {
	case fileRead:
		flag1 = GENERIC_READ;
		break;
	case fileAppend:
		flag1 = FILE_APPEND_DATA;
		flag2 = OPEN_ALWAYS;
		break;
	case fileModify:
		flag1 = GENERIC_WRITE;
		flag2 = OPEN_ALWAYS;
		break;
	case fileWrite:
		flag1 = GENERIC_WRITE;
		flag2 = CREATE_ALWAYS;
		break;
	case fileReadWrite:
		flag1 = GENERIC_READ | GENERIC_WRITE;
		break;
	case fileWriteRead:
		flag1 = GENERIC_READ | GENERIC_WRITE;
		flag2 = CREATE_ALWAYS;
		break;
	}
	return CreateFileW(path,
		flag1,
		share_flag,
		&sa,
		flag2,
		other_flag,
		NULL);
}
#endif
FILE_HANDLE kfopen(const char *path, fileModel model, int flag)
{
#ifdef _WIN32
	int share_flag = FILE_SHARE_READ | FILE_SHARE_WRITE;
	int other_flag = 0;
	if (KBIT_TEST(flag, KFILE_TEMP_MODEL)) {
		share_flag = 0;
		other_flag = (FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE);
	}
#ifndef KF_ASYNC_WORKER
	if (KBIT_TEST(flag, KFILE_ASYNC)) {
		KBIT_SET(other_flag, FILE_FLAG_OVERLAPPED);
	}
#endif
	if (KBIT_TEST(flag, KFILE_DSYNC)) {
		KBIT_SET(other_flag, FILE_FLAG_WRITE_THROUGH);
	}
	if (KBIT_TEST(flag, KFILE_SEQUENTIAL)) {
		KBIT_SET(other_flag, FILE_FLAG_SEQUENTIAL_SCAN);
	}
	SECURITY_ATTRIBUTES sa;
	memset(&sa, 0, sizeof(sa));
	sa.bInheritHandle = FALSE;
	int flag1 = 0;
	int flag2 = OPEN_EXISTING;
	switch (model) {
	case fileRead:
		flag1 = GENERIC_READ;
		break;
	case fileAppend:
		flag1 = FILE_APPEND_DATA;
		flag2 = OPEN_ALWAYS;
		break;
	case fileModify:
		flag1 = GENERIC_WRITE;
		flag2 = OPEN_ALWAYS;
		break;
	case fileWrite:
		flag1 = GENERIC_WRITE;
		flag2 = CREATE_ALWAYS;
		break;
	case fileReadWrite:
		flag1 = GENERIC_READ | GENERIC_WRITE;
		break;
	case fileWriteRead:
		flag1 = GENERIC_READ | GENERIC_WRITE;
		flag2 = CREATE_ALWAYS;
		break;
	}
	return CreateFileA(path,
		flag1,
		share_flag,
		&sa,
		flag2,
		other_flag,
		NULL);
#else
	int f = O_CLOEXEC;
#ifdef O_NOATIME
	if (KBIT_TEST(flag, KFILE_NOATIME)) {
		KBIT_SET(f, O_NOATIME);
	}
#endif
#ifdef O_LARGEFILE
	KBIT_SET(f, O_LARGEFILE);
#endif
	if (KBIT_TEST(flag, KFILE_NOFOLLOW)) {
		KBIT_SET(f, O_NOFOLLOW);
	}
	if (KBIT_TEST(flag, KFILE_DSYNC)) {
#ifdef O_DSYNC
		KBIT_SET(f, O_DSYNC);
#else
		KBIT_SET(f, O_SYNC);
#endif
	}
	switch (model) {
	case fileRead:
		f |= O_RDONLY;
		break;
	case fileAppend:
		f |= O_WRONLY | O_APPEND | O_CREAT;
		break;
	case fileModify:
		f |= (O_WRONLY | O_CREAT);
		break;
	case fileWrite:
		f |= (O_WRONLY | O_CREAT | O_TRUNC);
		break;
	case fileReadWrite:
		f |= O_RDWR;
		break;
	case fileWriteRead:
		f |= (O_RDWR | O_CREAT | O_TRUNC);
		break;
	}
	return open(path, f , 0644);
#endif
}
bool kfseek(FILE_HANDLE fp,int64_t len, seekPosion position)
{
#ifndef _WIN32
        int flag = 0;
        switch (position) {
        case seekBegin:
                flag = SEEK_SET;
                break;
        case seekEnd:
                flag = SEEK_END;
                break;
        case seekCur:
                flag = SEEK_CUR;
                break;
        }
#ifdef LINUX
        return lseek64(fp, len, flag) != -1;
#else
        return lseek(fp, len, flag) != -1;
#endif
#else
        int flag = 0;
        switch (position) {
        case seekBegin:
                flag = FILE_BEGIN;
                break;
        case seekEnd:
                flag = FILE_END;
                break;
        case seekCur:
                flag = FILE_CURRENT;
                break;
        }
        LARGE_INTEGER li;
        li.QuadPart = len;
        li.LowPart = SetFilePointer(fp, li.LowPart, &li.HighPart, flag);
        if (li.LowPart == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
                return false;
        }
        return true;
#endif
}


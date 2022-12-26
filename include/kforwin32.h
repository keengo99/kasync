#ifndef MSOCKET_FORWIN32_H
#define MSOCKET_FORWIN32_H
#include "kfeature.h"
KBEGIN_DECLS
#include <stdlib.h>
#ifdef _WIN32
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <stdio.h>
#include <process.h>
#include <windows.h>
#define KTHREAD_FUNCTION  void
#define KTHREAD_RETURN    return
#define snprintf _snprintf
#define O_SYNC	_O_WRONLY
#define pthread_create(a,b,c,d)		_beginthread(c,0,d)
#define PTHREAD_CREATE_SUCCESSED(x) (x!=-1)
#define lstat _stati64
#ifndef S_ISREG
#define S_ISREG(s)  (s & _S_IFREG)
#endif
#ifndef S_ISDIR
#define S_ISDIR(s)	(s & _S_IFDIR)
#endif
#define fseeko _fseeki64
#define pthread_key_t				DWORD
#define pthread_mutex_t 			HANDLE 
#define pthread_mutex_lock(x)	    WaitForSingleObject(*x,INFINITE)
#define pthread_mutex_unlock(x)		ReleaseMutex(*x)
INLINE char* kgl_strndup(const char* s, size_t n)
{
		size_t len;
		char* copy;
		len = strnlen(s, n);
		copy = (char *)malloc(n + 1);
		if (copy) {
			memcpy(copy, s, len);
			copy[len] = '\0';
		}
		return copy;
	
}
INLINE int pthread_key_delete(pthread_key_t key)
{
	if (TlsFree(key)) {
		return 0;
	}
	return -1;
}
INLINE int pthread_key_create(pthread_key_t *key, void *t)
{
	*key = TlsAlloc();
	if (*key == TLS_OUT_OF_INDEXES) {
		return 1;
	}
	return 0;
}
INLINE int pthread_setspecific(pthread_key_t key, void *arg)
{
	if (TlsSetValue(key, arg)) {
		return 0;
	}
	return 1;
}
INLINE void *pthread_getspecific(pthread_key_t key)
{
	return TlsGetValue(key);
}
INLINE int pthread_mutex_init(pthread_mutex_t *mutex,void *t)
{
	*mutex=CreateMutex(NULL,FALSE,NULL);
	return 0;
};
INLINE int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	CloseHandle(*mutex);
	return 0;
}
#define getpid()					GetCurrentProcessId()
#define pthread_self()				GetCurrentThreadId()
#define sleep(a)					Sleep(1000*a)
#define poll(a,b,c)                 WSAPoll(a,b,c)
#define pthread_t					unsigned

#ifndef bzero
#define bzero(x,y)	memset(x,0,y)
#endif
#define syslog		klog
#ifndef strncasecmp
#define		strncasecmp	_strnicmp
#endif
#ifndef strcasecmp
#define		strcasecmp	_stricmp
#endif
#ifndef strdup
#define		strdup		_strdup
#endif
#define		ERRNO			WSAGetLastError()
#define		CLOSE(so)		closesocket(so)
#define		strtok_r(a,b,c)		strtok(a,b)
#define ctime_r( _clock, _buf ) 	( strcpy( (_buf), ctime( (_clock) ) ), (_buf) )
#define gmtime_r( _clock, _result ) ( *(_result) = *gmtime( (_clock) ), (_result) )
#define localtime_r(a,b) localtime_s(b,a)
#define mkdir(a,b) _mkdir(a)
#define unlink(a)	_unlink(a)
#define PID_LIKE(x)  (x!=INVALID_HANDLE_VALUE)
#define filecmp		_stricmp
#define filencmp 	_strnicmp
#define pid_t       HANDLE
#define PATH_SPLIT_CHAR		'\\'
#define FILE_HANDLE     HANDLE
typedef HANDLE Token_t;
#define INT64_FORMAT     "%I64d"
#define INT64_FORMAT_HEX "%I64x"
//#ifndef PRId64
//#define PRId64 "I64d"
//#endif
#else
#include <inttypes.h>
#ifndef ntohll
#define ntohll be64toh
#define htonll htobe64
#endif
#define FILE_HANDLE     int
#define PID_LIKE(x)  (x>0)
#define PTHREAD_CREATE_SUCCESSED(x) (x==0)
typedef void * KTHREAD_FUNCTION;
#define KTHREAD_RETURN do { return NULL; }while(0)
#define filecmp		strcmp
#define filencmp 	strncmp
#define LoadLibrary(x) dlopen(x,RTLD_NOW|RTLD_LOCAL)
#define GetProcAddress dlsym
#define FreeLibrary	dlclose
#define SetDllDirectory(x)
#define GetLastError()	errno
#define _stati64 stat
#define _stat64 stat
#define kgl_strndup strndup
typedef int * Token_t;
#define PATH_SPLIT_CHAR		'/'
#define INT64_FORMAT     "%" PRId64
#define INT64_FORMAT_HEX "%llx"
#endif
#ifndef WIN32
#include <sys/types.h>
#include <sys/uio.h>
#define LOWORD(l)           ((unsigned)(l) & 0xffff)
#define HIWORD(l)           (((unsigned)(l) >> 16) & 0xffff)
#define MAKELONG(a, b)      (((unsigned)a & 0xffff) | ((unsigned)(b) & 0xffff) << 16)
#endif
KEND_DECLS
#endif

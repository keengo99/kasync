#ifndef KGLOBAL_H_99
#define KGLOBAL_H_99
#include "kasync_config.h"
#ifndef _WIN32
//#include "config.h"
#define INT64  int64_t
#define KSOCKET_UNIX
#define SOCKET  	int
#define INVALID_SOCKET  -1
#else
#define WIN32_LEAN_AND_MEAN 1
#define HAVE_SOCKLEN_T 1
#pragma warning(disable: 4290 4996 4819)
#endif
#ifdef  __cplusplus
	#define KBEGIN_DECLS  extern "C" {
	#define KEND_DECLS    }
	#define	INLINE	inline
#else
	#define KBEGIN_DECLS
	#define KEND_DECLS
	#ifdef _WIN32
	#define INLINE __forceinline
	#else
	#define INLINE	inline __attribute__((always_inline))
	#endif
#endif
#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif
#if defined(_MSC_VER) && _MSC_VER < 1600
typedef char				int8_t;
typedef short				int16_t;
typedef int					int32_t;
typedef __int64				int64_t;
typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned long		uint32_t;
typedef unsigned __int64    uint64_t;
#define bool				uint8_t
#define true				1
#define false				0
#else
#include <stdint.h>
#include <stdbool.h>
#endif
KBEGIN_DECLS
#if defined(FREEBSD) || defined(NETBSD) || defined(OPENBSD) || defined(DARWIN)
#define BSD_OS 1
#endif
#ifndef NDEBUG
#if defined(LINUX) || defined(_WIN32)
//#define MALLOCDEBUG	1
#endif
#endif

#if defined(LINUX) && !defined(LINUX_IOURING)
#define LINUX_EPOLL 1
#endif

#if defined(LINUX_IOURING) || defined(_WIN32)
//LINUX io_uring and win32 are iocp model
#define KGL_IOCP       1
#endif
//#define KSOCKET_SSL     1
#define KSOCKET_IPV6	1
#define ENABLE_PROXY_PROTOCOL      1
//#define ENABLE_FIBER    1
#ifdef KSOCKET_SSL
#ifdef KGL_IOCP
#define ENABLE_KSSL_BIO 1
#endif
#endif
#define kgl_countof(array) (sizeof(array) / sizeof(array[0]))

#define KBIT_SET(a,b)   ((a)|=(b))
#define KBIT_CLR(a,b)   ((a)&=~(b))
#define KBIT_TEST(a,b)  ((a)&(b))
#define SAFE_STRCPY(s,s1)   do {memset(s,0,sizeof(s));strncpy(s,s1,sizeof(s)-1);}while(0)
#ifndef MAX
#define MAX(a,b)  ((a)>(b)?(a):(b))
#endif
#ifndef MIN
#define MIN(a,b)  ((a)>(b)?(b):(a))
#endif
#define        IS_SPACE(a)     isspace((unsigned char)a)
#define        IS_DIGIT(a)     isdigit((unsigned char)a)
#if defined(__GNUC__) && (__GNUC__ > 2)
# define likely(x)   __builtin_expect((x),1)
# define unlikely(x) __builtin_expect((x),0)
#else
# define likely(x)   (x)
# define unlikely(x) (x)
#endif
typedef enum {
	kev_ok, //selectable in selector event(read/write/next/connect) or timer or by user blocked.
	kev_fiber_ok, //selectable handle by fiber callback.
	kev_err,//selectable not in any selector event/timer and not destroy
	kev_destroy//selectable not in any selector event/timer and destroied by result callback
} kev_result;

#define KEV_HANDLED(x) (x!=kev_err)
#define KEV_AVAILABLE(x) (x!=kev_destroy)
#ifdef _WIN32
	#ifndef iovec
		#define iovec          _WSABUF
		#define iov_base       buf
		#define iov_len        len
	#endif
#else
#include <netdb.h>
typedef struct iovec WSABUF;
typedef WSABUF * LPWSABUF;
#endif

#if defined _WIN32 || defined __CYGWIN__
#define DLL_PUBLIC __declspec(dllexport)
#else
#if __GNUC__ >= 4
#define DLL_PUBLIC __attribute__ ((visibility("default")))
#else
#define DLL_PUBLIC
#endif
#endif

#define ST_ERR_RESULT      -1
#define ST_ERR_TIME_OUT    -2
#define ST_ERR_RESOLV      -3
typedef volatile int32_t kcountable_t;
typedef struct {
	struct addrinfo* addr;
	kcountable_t refs;
} kgl_addr;

typedef kev_result(*kgl_addr_call_back)(void* arg, kgl_addr* addr);

typedef void * KOPAQUE;
typedef kev_result(*result_callback)(KOPAQUE data, void *arg, int got);
typedef int (*buffer_callback)(KOPAQUE data, void *arg, struct iovec *buf, int bc);
typedef void(*kgl_cleanup_f) (void *data);
#define kgl_expand_string(str)  (char *)str ,sizeof(str) - 1

#define KFILE_TEMP_MODEL       1
#define KFILE_ASYNC            2
#define KFILE_NOFOLLOW         4
#define KFILE_DSYNC            8
typedef enum _seekPosion
{
	seekBegin,
	seekEnd,
	seekCur
} seekPosion;

typedef enum _fileModel
{
	fileRead,
	fileWrite,//truncate
	fileModify,
	fileReadWrite,
	fileWriteRead,//truncate
	fileAppend
} fileModel;
KEND_DECLS
#endif

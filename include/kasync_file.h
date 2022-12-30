#ifndef KASYNC_FILE_H_99
#define KASYNC_FILE_H_99
#include "kselectable.h"
#include "kfeature.h"
#include "kfile.h"
#ifdef LINUX
#include <linux/aio_abi.h>
#elif BSD_OS
#include <aio.h>
#endif
KBEGIN_DECLS
#ifdef DARWIN
#define KF_ASYNC_WORKER 1
#endif
#ifdef LINUX_EPOLL
#define KF_ASYNC_WORKER 1
#endif
#ifdef KF_ASYNC_WORKER
typedef struct _kf_aiocb kf_aiocb;
typedef enum _kf_aio_cmd {
        kf_aio_read,
        kf_aio_write,
} kf_aio_cmd;

struct _kf_aiocb {
        kf_aio_cmd cmd;
};
#endif

void init_aio_align_size();
void *aio_alloc_buffer(size_t size);
void aio_free_buffer(void *buf);
kev_result result_async_file_event(KOPAQUE data, void *arg, int got);
struct kasync_file_s {
	union {
#ifdef LINUX_EPOLL
		struct iocb iocb;
#endif
#ifdef BSD_OS
		struct aiocb iocb;
#endif
#ifdef KF_ASYNC_WORKER
		kf_aiocb kiocb;
#endif
	};
#ifdef KF_ASYNC_WORKER
	int offset_adjust;
	int length;
	FILE_HANDLE fd;
	int flags;
	KOPAQUE data;
	kselector *selector;
#else
	kselectable st;
#endif
	char *buf; //deprecated
	void *arg;
	aio_callback cb;
};
INLINE FILE_HANDLE kasync_file_get_handle(kasync_file *fp)
{
#ifdef  KF_ASYNC_WORKER
	return fp->fd;
#else
	return (FILE_HANDLE)fp->st.fd;
#endif
}
void async_file_event(kasync_file *fp,char *buf,int got);
INLINE void kasync_file_close(kasync_file *fp)
{
	kfclose(kasync_file_get_handle(fp));
}
INLINE kselector *kasync_file_get_selector(kasync_file *fp)
{
#ifdef KF_ASYNC_WORKER
	return fp->selector;
#else
	return fp->st.selector;
#endif
}
INLINE void kasync_file_bind_opaque(kasync_file *fp, KOPAQUE data)
{
#ifdef KF_ASYNC_WORKER
	fp->data = data;
#else
	fp->st.data = data;
#endif
}
INLINE KOPAQUE kasync_file_get_opaque(kasync_file *fp)
{
#ifdef KF_ASYNC_WORKER
	return fp->data;
#else
	return fp->st.data;
#endif
}
KEND_DECLS
#endif

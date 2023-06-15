#ifndef KASYNC_FILE_H_99
#define KASYNC_FILE_H_99
#include <assert.h>
#include "kselectable.h"
#include "kfeature.h"
#include "kfile.h"
#ifdef LINUX
#include <linux/aio_abi.h>
#elif BSD_OS
#include <aio.h>
#endif
KBEGIN_DECLS

#ifdef KF_ASYNC_WORKER
typedef struct _kf_aiocb kf_aiocb;
typedef enum _kf_aio_cmd
{
	kf_aio_read,
	kf_aio_write,
} kf_aio_cmd;

struct _kf_aiocb
{
	int length;
	char* buf;
	kf_aio_cmd cmd;
};
bool kasync_file_worker_start(kasync_file *file);
#endif

void init_aio_align_size();
void* aio_alloc_buffer(size_t size);
void aio_free_buffer(void* buf);

struct kasync_file_s
{
#if defined(LINUX_EPOLL) || defined(BSD_OS) || defined(KF_ASYNC_WORKER)
	union
	{
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
#endif
	kselectable st;
};
INLINE FILE_HANDLE kasync_file_get_handle(kasync_file* fp) {
	return (FILE_HANDLE)fp->st.fd;
}
INLINE void kasync_file_close(kasync_file* fp) {
	kfclose(kasync_file_get_handle(fp));
}
INLINE kselector* kasync_file_get_selector(kasync_file* fp) {
	return fp->st.base.selector;
}
INLINE void kasync_file_bind_opaque(kasync_file* fp, KOPAQUE data) {
	fp->st.data = data;
}
INLINE KOPAQUE kasync_file_get_opaque(kasync_file* fp) {
	return fp->st.data;
}
#if defined(O_DIRECT) && defined(LINUX_EPOLL)
INLINE int64_t _kasync_file_get_adjust_offset(kasync_file *fp) {
	return fp->st.offset - (int16_t)fp->st.direct_io_offset;
}
INLINE int kasync_file_adjust_result(kasync_file *fp,int got)
{	
	assert(fp->st.direct_io_offset>=0);
	if (!fp->st.direct_io) {
		return got;
	}	
	assert(got>fp->st.direct_io_offset);
	if (got < fp->st.direct_io_offset) {
		return -1;
	}
	got -= fp->st.direct_io_offset;
	return KGL_MIN(got,fp->st.direct_io_orig_length);
}
bool kasync_file_direct(kasync_file *fp, bool on_flag);
#else
#define kasync_file_direct(x,y) true
#define kasync_file_adjust_result(file,got) got
#define _kasync_file_get_adjust_offset(file) (file->st.offset)
#endif
KEND_DECLS
#endif

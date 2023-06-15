#ifndef KCOROUTINE_H
#define KCOROUTINE_H
#include "kfeature.h"
#include "ksync.h"
#include "kselectable.h"
#include "ksocket.h"
#include "kasync_file.h"
#include "kconnection.h"
#include "kserver.h"
#include "kfiber_internal.h"
#include "kaddr.h"
#include "kbuf.h"

KBEGIN_DECLS
#define _ST_PAGE_SIZE 4096


typedef kasync_file kfiber_file;
typedef struct _kfiber_chan kfiber_chan;


//init
void kfiber_init();

//fiber
int kfiber_get_count();
//create a paused fiber
kfiber* kfiber_new(kfiber_start_func start, void* start_arg, int stk_size);

int kfiber_start(kfiber* fiber,int len);
int kfiber_create2(kselector *selector, kfiber_start_func start, void *start_arg, int len, int stk_size, kfiber** fiber);
INLINE int kfiber_create(kfiber_start_func start, void* arg, int len, int stk_size, kfiber** fiber) {
	return kfiber_create2(NULL, start, arg, len, stk_size, fiber);
}
int kfiber_create_sync(kfiber_start_func start, void* start_arg, int len, int stk_size, kfiber** fiber);
//void kfiber_yield();
//kfiber next deprecated
bool kfiber_has_next();
int kfiber_next(kfiber_start_func start, void* start_arg, int len);
kfiber *kfiber_self();

kfiber *kfiber_ref_self(bool thread_safe);


int kfiber_join(kfiber *fiber,int *retval);
int kfiber_try_join(kfiber* fiber, int* retval);
kev_result kfiber_join2(kfiber *fiber, KOPAQUE data, result_callback notice, void *arg);

int kfiber_exit_callback(KOPAQUE data, result_callback notice, void *arg);
bool kfiber_is_main();
int kfiber_msleep(int msec);
void kfiber_wakeup(kfiber *fiber,void *obj, int retval);
void kfiber_wakeup_ts(kfiber* fiber, void* obj, int retval);
int kfiber_wait(void *obj);
int __kfiber_wait(kfiber *fiber, void* obj);

//chan
kfiber_chan *kfiber_chan_create(int buf_size);
int kfiber_chan_send(kfiber_chan *ch, void *data, int len);
int kfiber_chan_recv(kfiber_chan *ch, void **data);
int kfiber_chan_shutdown(kfiber_chan *ch);
kfiber_chan* kfiber_chan_add_ref(kfiber_chan* ch);
int kfiber_chan_close(kfiber_chan *ch);

//socket
#define kfiber_net_open kconnection_new
#define kfiber_net_open2 kconnection_new2
int kfiber_net_listen(kserver* server, int flag, kserver_selectable **ss);
int kfiber_net_accept(kserver_selectable* ss, kconnection **cn);
int kfiber_net_getaddr(const char *hostname, kgl_addr **addr);
int kfiber_net_connect(kconnection *cn, sockaddr_i *bind_addr, int tproxy_mask);
int kfiber_net_write(kconnection *cn, const char *buf, int len);
int kfiber_net_writev(kconnection *cn, WSABUF *buf, int vc);
int kfiber_net_read(kconnection *cn, char *buf, int len);

int kfiber_sendfile(kconnection* cn, kfiber_file* fp, int len);
INLINE bool kfiber_sendfile_full(kconnection* cn, kfiber_file* fp, int* len) {
	while (*len > 0) {
		int got = kfiber_sendfile(cn, fp, *len);
		if (got <= 0) {
			return false;
		}
		*len -= got;
	}
	return true;
}
INLINE bool kfiber_net_writev_full(kconnection *cn, WSABUF *buf, int *vc)
{
	while (*vc > 0) {
		int got = kfiber_net_writev(cn, buf, *vc);
		if (got <= 0) {
			return false;
		}
		while (got > 0) {
			if ((int)buf->iov_len > got) {
				buf->iov_len -= got;
				buf->iov_base = (char *)buf->iov_base + got;
				break;
			}
			got -= (int)buf->iov_len;			
			buf ++;
			(*vc) --;
		}
	}
	return true;
}
#if 0
/* length is -1 will write all buf data. */
INLINE bool kfiber_net_write_buf_full(kconnection* cn, kbuf* buf, int length) {

#define KGL_RQ_WRITE_BUF_COUNT 32
	WSABUF bufs[KGL_RQ_WRITE_BUF_COUNT];
	while (buf) {
		int bc = 0;
		while (bc < KGL_RQ_WRITE_BUF_COUNT && buf) {
			if (length == 0) {
				break;
			}
			if (length > 0) {
				bufs[bc].iov_len = KGL_MIN(length, buf->used);
				length -= bufs[bc].iov_len;
			} else {
				bufs[bc].iov_len = buf->used;
			}
			bufs[bc].iov_base = buf->data;
			buf = buf->next;
			bc++;
		}
		if (bc == 0) {
			if (length > 0) {
				return false;
			}
			assert(length == 0);
			return true;
		}
		if (!kfiber_net_writev_full(cn, bufs, &bc)) {
			return false;
		}
	}
	return true;
}
#endif
INLINE bool kfiber_net_write_full(kconnection *cn, const char *buf, int *len)
{
	while (*len > 0) {
		int got = kfiber_net_write(cn, buf, *len);
		if (got <= 0) {
			return false;
		}
		buf += got;
		*len -= got;
	}
	return true;
}
INLINE bool kfiber_net_read_full(kconnection *cn, char *buf, int *len)
{
	while (*len > 0) {
		int got = kfiber_net_read(cn, buf, *len);
		if (got <= 0) {
			return false;
		}
		buf += got;
		*len -= got;
	}
	return true;
}
int kfiber_net_readv(kconnection *cn, WSABUF *buf, int vc);
int kfiber_net_close(kconnection *cn);
int kfiber_net_shutdown(kconnection *cn);
#ifdef KSOCKET_SSL
int kfiber_ssl_handshake(kconnection *cn);
#endif

//udp
int kfiber_udp_readv(kconnection* cn, WSABUF* buf, int vc);
int kfiber_udp_read(kconnection* cn, char *buf,int len);
//file
kfiber_file *kfiber_file_open(const char *filename, fileModel model, int kf_flags);
kfiber_file* kfiber_file_bind(FILE_HANDLE fp);

int64_t kfiber_file_size(kfiber_file *fp);
int kfiber_file_read(kfiber_file *fp, char *buf, int length);
int kfiber_file_write(kfiber_file *fp, const char *buf, int length);
INLINE bool kfiber_file_write_full(kfiber_file* fp, const char* buf, int *length)
{
	while (*length > 0) {
		int got = kfiber_file_write(fp, buf, *length);
		if (got <= 0) {
			return false;
		}
		*length -= got;
		buf += got;
	}
	return true;
}
INLINE bool kfiber_file_read_full(kfiber_file* file, char* buf, int *length) {
	while (*length > 0) {
		int got = kfiber_file_read(file, buf, *length);
		if (got <= 0) {
			return false;
		}
			*length -= got;
			buf += got;
	}
	return true;
}
void kfiber_file_close(kfiber_file *fp);
int kfiber_file_seek(kfiber_file *fp, seekPosion pos, int64_t offset);
int64_t kfiber_file_tell(kfiber_file *fp);
#if defined(O_DIRECT) && defined(LINUX_EPOLL)
#define kfiber_file_adjust(file,buf) (const char *)(buf + file->st.direct_io_offset)
#else
#define kfiber_file_adjust(file,buf) (const char *)(buf)
#endif

//thread call
int kfiber_thread_call(kfiber_start_func start, void* arg, int argc, int *ret);
KEND_DECLS
#endif

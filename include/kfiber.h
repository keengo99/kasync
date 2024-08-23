#ifndef KCOROUTINE_H
#define KCOROUTINE_H
#include "kfeature.h"
#include "ksync.h"
#include "ksocket.h"
#include "kasync_file.h"
#include "kconnection.h"
#include "kserver.h"
#include "kfiber_internal.h"
#include "kaddr.h"
#include "kbuf.h"

KBEGIN_DECLS
#define _ST_PAGE_SIZE 4096
#define KFIBER_WAIT_CODE(obj) obj

extern pthread_key_t kgl_current_fiber_key;
typedef kasync_file kfiber_file;


//init
void kfiber_init();

//fiber
int kfiber_get_count();
//create a paused fiber
kfiber* kfiber_new(kfiber_start_func start, void* start_arg, int stk_size);
const char* kfiber_powered_by();
int kfiber_start(kfiber* fiber,int len);
int kfiber_create2(kselector *selector, kfiber_start_func start, void *start_arg, int len, int stk_size, kfiber** fiber);
INLINE int kfiber_create(kfiber_start_func start, void* arg, int len, int stk_size, kfiber** fiber) {
	return kfiber_create2(NULL, start, arg, len, stk_size, fiber);
}
int kfiber_create_sync(kfiber_start_func start, void* start_arg, int len, int stk_size, kfiber** fiber);
//void kfiber_yield();
//kfiber next deprecated
//bool kfiber_has_next();
//int kfiber_next(kfiber_start_func start, void* start_arg, int len);
INLINE kfiber* kfiber_self() {
	return (kfiber*)pthread_getspecific(kgl_current_fiber_key);
}
kfiber *kfiber_ref_self(bool thread_safe);


int kfiber_join(kfiber *fiber,int *retval);
int kfiber_try_join(kfiber* fiber, int* retval);
kev_result kfiber_join2(kfiber *fiber, KOPAQUE data, result_callback notice, void *arg);

int kfiber_exit_callback(KOPAQUE data, result_callback notice, void *arg);
bool kfiber_is_main();
int kfiber_msleep(int msec);
void __kfiber_switch(kfiber* fiber_from, kfiber* fiber_to);
INLINE void kfiber_wakeup(kfiber* fiber, void* obj, int ret) {
	kfiber* fiber_from = kfiber_self();
	kassert(fiber_from);
	kassert(fiber_from->base.selector);
	kassert(fiber->base.selector);
	kassert(fiber_from->base.selector == fiber->base.selector);
#ifndef NDEBUG
	if (fiber->wait_flag) {
		kassert(KFIBER_WAIT_CODE(obj) == fiber->wait_code);
		if (KFIBER_WAIT_CODE(obj) != fiber->wait_code) {
			//klog(KLOG_ERR, "BUG wakeup fiber=[%p] not expected,wakeup code=[%p], wait code=[%p]\n", fiber, KFIBER_WAIT_CODE(obj), fiber->wait_code);
			abort();
		}
	} else {
		fiber->wait_code = KFIBER_WAIT_CODE(obj);
	}
	fiber->notice_flag = 1;
#endif
	fiber->retval = ret;
	if (fiber_from == fiber) {
		return;
	}
	assert(fiber_from != fiber);
	fiber->switch_from = fiber_from;
	__kfiber_switch(fiber_from, fiber);
}
void kfiber_wakeup_ts(kfiber* fiber, void* obj, int retval);
INLINE int __kfiber_wait(kfiber* fiber, void* obj) {
	kassert(fiber->switch_from);
	kassert(fiber == kfiber_self());
#ifndef NDEBUG
	if (fiber->notice_flag) {
		assert(fiber->wait_code == KFIBER_WAIT_CODE(obj));
		if (KFIBER_WAIT_CODE(obj) != fiber->wait_code) {
			//klog(KLOG_ERR, "BUG __kfiber_wait fiber=[%p] not expected,wakeup code=[%p], wait code=[%p]\n", fiber, KFIBER_WAIT_CODE(obj), fiber->wait_code);
			abort();
		}
	} else {
		fiber->wait_code = KFIBER_WAIT_CODE(obj);
	}
	fiber->wait_flag = 1;
#endif
	__kfiber_switch(fiber, fiber->switch_from);
	return fiber->retval;
}
INLINE int kfiber_wait(void* obj) {
	kfiber* fiber = kfiber_self();
#ifndef NDEBUG
	fiber->wait_notice_flag = 0;
#endif
	return __kfiber_wait(fiber, obj);
}

INLINE void _kfiber_wakeup_waiter(kfiber_waiter* waiter, void *obj, int got) {
	if (waiter->st_flags == STF_FIBER) {
		kfiber* fiber = kgl_list_data(waiter, kfiber, base);
#ifndef NDEBUG
		fiber->base.next = NULL;
#endif
		kfiber_wakeup_ts(fiber, obj, got);
		return;
	}
	assert(waiter->st_flags == 0);
	kfiber_event_waiter* ev_waiter = kgl_list_data(waiter, kfiber_event_waiter, base);
	kgl_selector_module.next(waiter->selector, obj, ev_waiter->result, ev_waiter->arg, got);
	xfree(ev_waiter);
}

INLINE void kfiber_wakeup_waiter(kfiber_waiter* waiter, int got) {
	_kfiber_wakeup_waiter(waiter, waiter->wait_obj, got);
}
INLINE void kfiber_wakeup_all_waiter(kfiber_waiter* waiter, int got) {
	while (waiter) {
		kfiber_waiter* next = waiter->next;
		kfiber_wakeup_waiter(waiter, got);
		waiter = next;
	}
}
void kfiber_add_ev_waiter(kfiber_waiter** head, kselector* selector, KOPAQUE data, result_callback notice, void* arg);
INLINE void kfiber_add_waiter(kfiber_waiter** head, kfiber* fiber, KOPAQUE data) {
	fiber->base.wait_obj = data;
	fiber->base.next = *head;
	*head = &fiber->base;
}
//socket
#define kfiber_net_open kconnection_new
#define kfiber_net_open2 kconnection_new2
int kfiber_net_listen(kserver* server, int flag, kserver_selectable **ss);
int kfiber_net_accept(kserver_selectable* ss, kconnection **cn);
int kfiber_net_getaddr(const char *hostname, kgl_addr **addr);
int kfiber_net_connect(kconnection *cn, sockaddr_i *bind_addr, int tproxy_mask);
INLINE int kfiber_net_writev2(kfiber* fiber, kconnection* cn, kgl_iovec* buf, int bc) {
	CHECK_FIBER(fiber);
	kgl_iovec iovec_buf;
	iovec_buf.iov_base = (char*)buf;
	iovec_buf.iov_len = bc;
#ifndef KGL_IOCP
	if (!selectable_get_ssl(&cn->st) && KBIT_TEST(cn->st.base.st_flags, STF_WREADY)) {
		if (kev_fiber_ok != selectable_event_write(&cn->st, kfiber_result_callback, &iovec_buf, fiber)) {
			__kfiber_wait(fiber, cn->st.data);
		}
		return fiber->retval;
	}
#endif
	if (kev_fiber_ok != selectable_write(&cn->st, kfiber_result_callback, &iovec_buf, fiber)) {
		__kfiber_wait(fiber, cn->st.data);
	}
	return fiber->retval;
}

INLINE int kfiber_net_writev(kconnection *cn, kgl_iovec *buf, int bc) {
	return kfiber_net_writev2(kfiber_self(), cn, buf, bc);
}
INLINE int kfiber_net_write(kconnection* cn, const char* buf, int len) {
	kgl_iovec v;
	v.iov_base = (char*)buf;
	v.iov_len = len;
	return kfiber_net_writev(cn, &v, 1);
}
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
INLINE bool kfiber_net_writev_full(kconnection* cn, WSABUF* buf, int* vc) {
	while (*vc > 0) {
		int got = kfiber_net_writev(cn, buf, *vc);
		if (got <= 0) {
			return false;
		}
		while (got > 0) {
			if ((int)buf->iov_len > got) {
				buf->iov_len -= got;
				buf->iov_base = (char*)buf->iov_base + got;
				break;
			}
			got -= (int)buf->iov_len;
			buf++;
			(*vc)--;
		}
	}
	return true;
}

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
INLINE int kfiber_net_readv2(kfiber* fiber, kconnection* cn, kgl_iovec* buf, int bc) {
	CHECK_FIBER(fiber);
	kgl_iovec iovec_buf;
	iovec_buf.iov_base = (char*)buf;
	iovec_buf.iov_len = bc;
	if (KBIT_TEST(cn->st.base.st_flags, STF_READ)) {
		/*
			connection already has read event.
			this condition only happened in read timeout
		*/
		assert(KBIT_TEST(cn->st.base.st_flags, STF_RTIME_OUT));
		assert(cn->st.e[OP_READ].result == kfiber_result_callback);
		//assert(cn->st.e[OP_READ].buffer == kfiber_buffer_callback);
		assert(cn->st.e[OP_READ].arg == fiber);
		return __kfiber_wait(fiber, cn->st.data);
	}
	if (kev_fiber_ok != selectable_read(&cn->st, kfiber_result_callback, &iovec_buf, fiber)) {
		return __kfiber_wait(fiber, cn->st.data);
	}
	return fiber->retval;
}
INLINE int kfiber_net_readv(kconnection * cn, kgl_iovec* buf,int bc) {
	return kfiber_net_readv2(kfiber_self(), cn, buf, bc);
}

INLINE int kfiber_net_read(kconnection *cn, char *buf, int len) {
	kgl_iovec v;
	v.iov_base = (char*)buf;
	v.iov_len = len;
	return kfiber_net_readv(cn, &v, 1);
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
int kfiber_net_close(kconnection *cn);
int kfiber_net_shutdown(kconnection *cn);
#ifdef KSOCKET_SSL
int kfiber_ssl_handshake(kconnection *cn);
#endif

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
/*
* kfiber_file_safe_* func allow the caller and file's selector be different.
*/
bool kfiber_file_safe_write_full(kfiber_file* fp, const char* buf, int* length);
int kfiber_file_safe_read(kfiber_file* fp, char* buf, int length);

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

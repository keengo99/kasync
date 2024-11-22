#ifndef MSOCKET_SELECTABLE_H
#define MSOCKET_SELECTABLE_H
#include "kfeature.h"
#include "kgl_ssl.h"
#include "kforwin32.h"
#include "kselector.h"
#include "kfiber_internal.h"
#include "klist.h"
#include "ksocket.h"
#include "kmalloc.h"

#define STF_READ        1
#define STF_WRITE       (1<<1)
#define STF_RDHUP       (1<<2)
#define STF_SENDFILE    (1<<3)

#ifndef KGL_IOCP
#define STF_REV         (1<<4)
#define STF_WEV         (1<<5)
#define STF_ET          (1<<6)
#else
#ifdef  LINUX_IOURING
#define STF_USEPOLL     (1<<6) /* iouring use for poll model */
#elif  _WIN32
#define STF_IOCP_BINDED (1<<6)
#endif
#endif
#define STF_ERR         (1<<7)

#define STF_RREADY      (1<<8)
#define STF_WREADY      (1<<9)

#define STF_RREADY2     (1<<10)
#define STF_WREADY2     (1<<11)

#define STF_RTIME_OUT   (1<<12)
#define STF_UDP         (1<<13)

#define STF_FIBER       (1<<14)
#define STF_AIO_FILE    (1<<15)

#define STF_REVENT      (STF_READ)
#define STF_WEVENT      (STF_WRITE|STF_RDHUP)
#define STF_EVENT       (STF_REVENT|STF_WEVENT)

#define STF_RLOCK       STF_READ
#define STF_WLOCK       STF_WRITE
#define STF_LOCK        (STF_RLOCK|STF_WLOCK)


#define MAX_IOVECT_COUNT 128

KBEGIN_DECLS
kev_result selectable_read_event(kselectable* st);
kev_result selectable_write_event(kselectable* st);
kev_result selectable_event_read(kselectable* st, result_callback result, buffer_callback buffer, void* arg);
kev_result selectable_event_write(kselectable* st, result_callback result, buffer_callback buffer, void* arg);
struct kselectable_s
{
	kgl_base_selectable base;/* must at begin */
	SOCKET fd;
#ifdef RQ_LEAK_DEBUG
	kgl_list queue_edge;
#endif
	KOPAQUE data;
	kgl_event e[2];
	union {
		struct {
			/* fd is socket. */
			int64_t active_msec;	
#ifdef KSOCKET_SSL
			kssl_session* ssl;
#endif		
		};
		struct {
			/* fd is aio file. */
			int64_t   offset;
#if defined(O_DIRECT) && defined(LINUX_EPOLL)
			int       direct_io_orig_length;
			uint16_t  direct_io_offset;
			uint16_t  direct_io:1;
#endif
		};
	};
};

INLINE void kselector_add_fiber_ready(kselector* selector, kfiber* fiber) {
	kassert(kselector_is_same_thread(selector));
	kassert(fiber->base.selector == selector);
	kassert(fiber->base.queue.next == NULL);
	selector->count++;
	klist_append(&selector->list[KGL_LIST_READY], &fiber->base.queue);
}

INLINE void kselector_add_list(kselector* selector, kselectable* st, int list) {
	kassert(kselector_is_same_thread(selector));
	st->base.tmo_left = st->base.tmo;
	kassert(st->base.selector == selector);
	if (list != KGL_LIST_READY) {
		st->active_msec = kgl_current_msec;
	}
	kassert(list >= 0 && list < KGL_LIST_COUNT);
	if (st->base.queue.next) {
		klist_remove(&st->base.queue);
	} else {
		selector->count++;
	}
	klist_append(&selector->list[list], &st->base.queue);
}
INLINE kev_result kselectable_is_read_ready(kselector* selector, kselectable* st) {
	if (kselector_is_main_fiber(selector)) {
		kselector_add_list(selector, st, KGL_LIST_READY);
		return kev_ok;
	}
	return selectable_read_event(st);
}
INLINE kev_result kselectable_is_write_ready(kselector* selector, kselectable* st) {
	if (kselector_is_main_fiber(selector)) {
		kselector_add_list(selector, st, KGL_LIST_READY);
		return kev_ok;
	}
	return selectable_write_event(st);
}
INLINE void kselector_remove_list(kselector* selector, kselectable* st) {
	kassert(kselector_is_same_thread(selector));
	kassert(st->base.selector == selector);
	if (st->base.queue.next == NULL) {
		return;
	}
	klist_remove(&st->base.queue);
	memset(&st->base.queue, 0, sizeof(st->base.queue));
	kassert(selector->count > 0);
	selector->count--;
}
INLINE KOPAQUE selectable_get_opaque(kselectable* st) {
	return st->data;
}
INLINE void selectable_bind_opaque(kselectable* st, KOPAQUE data) {
	st->data = data;
}
void selectable_clean(kselectable* st);
bool selectable_remove(kselectable* st);
INLINE void selectable_next(kselectable* st, result_callback result, void* arg, int got) {
	kgl_selector_module.next(st->base.selector, st->data, result, arg, got);
}
INLINE bool selectable_support_sendfile(kselectable* st) {
#ifdef KSOCKET_SSL
	if (st->ssl) {
		return kgl_ssl_support_sendfile(st->ssl);
	}
#endif	
	return true;
}
void selectable_next_read(kselectable* st, result_callback result, void* arg);
void selectable_next_write(kselectable* st, result_callback result, void* arg);
/**
* selectable_read & selectable_write
* buffer->iov_base store real struct iovec
* buffer->iov_len store count of struct iovec
* and buffer must be available until result callback.
*/
kev_result selectable_read(kselectable* st, result_callback result, kgl_iovec *buffer, void* arg);
kev_result selectable_write(kselectable* st, result_callback result, kgl_iovec *buffer, void* arg);
INLINE kev_result selectable_sendfile(kselectable* st, result_callback result, kgl_iovec* buffer, void* arg) {
	return kgl_selector_module.sendfile(st, result, buffer, arg);
	/*
	if (!kgl_selector_module.sendfile(st, result, buffer, arg)) {
		return result(st->data,arg,-1);
	}
	return kev_ok;
	*/
}
bool selectable_readhup(kselectable* st, result_callback result, void* arg);
void selectable_remove_readhup(kselectable* st);
INLINE int selectable_shutdown(kselectable* st) {
#ifdef _WIN32
	ksocket_cancel(st->fd);
#endif
	return ksocket_shutdown(st->fd, SHUT_RDWR);
}
INLINE void selectable_clear_flags(kselectable* st, uint16_t flags) {
	KBIT_CLR(st->base.st_flags, flags);
}
INLINE void selectable_bind(kselectable* st, kselector* selector) {
	kgl_selector_module.bind(selector, st);
}
INLINE bool is_selectable(kselectable* st, uint16_t flags) {
	return KBIT_TEST(st->base.st_flags, flags) > 0;
}
INLINE bool selectable_is_locked(kselectable* st) {
	return is_selectable(st, STF_LOCK);
}
INLINE kssl_session* selectable_get_ssl(kselectable* st) {
#ifdef KSOCKET_SSL
	return st->ssl;
#else
	return NULL;
#endif
}
INLINE bool selectable_is_ssl_handshake(kselectable* st) {
#ifdef KSOCKET_SSL
	return st->ssl && st->ssl->handshake;
#else
	return false;
#endif
}
#ifndef _WIN32
int selectable_recvmsg(kselectable* st);
#endif
KEND_DECLS
#endif

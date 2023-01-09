#ifndef MSOCKET_SELECTABLE_H
#define MSOCKET_SELECTABLE_H
#include "kfeature.h"
#include "kgl_ssl.h"
#include "kforwin32.h"
#include "kselector.h"
#include "klist.h"
#include "ksocket.h"

#define STF_READ        1
#define STF_WRITE       (1<<1)
#define STF_RDHUP       (1<<2)
#define STF_SENDFILE    (1<<3)

#define STF_REV         (1<<4)
#define STF_WEV         (1<<5)
#ifndef KGL_IOCP
#define STF_ET          (1<<6)
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

typedef void(*kgl_void_f)();
typedef struct
{
	void* arg;
	union
	{
		result_callback result;
		kgl_void_f void_result;
	};
	union
	{
		buffer_callback buffer;
		kgl_void_f void_buffer;
	};
} kgl_app_event;

typedef struct
{
	kgl_app_event ev;
	void* arg;
} kgl_stack_context;

typedef struct
{

	struct
	{
		void* arg;
		result_callback result;
		union
		{
			buffer_callback buffer;
			void* buffer_ctx;
		};
	};

#ifdef _WIN32
	WSAOVERLAPPED lp;
#endif
#ifdef LINUX_IOURING
	kselectable* st;
#endif
} kgl_event;

struct kselectable_s
{
	kgl_list queue;
	kselector* selector;
	uint16_t st_flags;
	/* same as kfiber */
	uint8_t tmo_left;
	uint8_t tmo;
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
inline KOPAQUE selectable_get_opaque(kselectable* st) {
	return st->data;
}
inline void selectable_bind_opaque(kselectable* st, KOPAQUE data) {
	st->data = data;
}
void selectable_clean(kselectable* st);
bool selectable_remove(kselectable* st);
INLINE void selectable_next(kselectable* st, result_callback result, void* arg, int got) {
	kgl_selector_module.next(st->selector, st->data, result, arg, got);
}
INLINE bool selectable_support_sendfile(kselectable* st) {
	return kgl_selector_module.support_sendfile(st);
}
void selectable_next_read(kselectable* st, result_callback result, void* arg);
void selectable_next_write(kselectable* st, result_callback result, void* arg);

kev_result selectable_read(kselectable* st, result_callback result, buffer_callback buffer, void* arg);
kev_result selectable_write(kselectable* st, result_callback result, buffer_callback buffer, void* arg);
bool selectable_try_read(kselectable* st, result_callback result, buffer_callback buffer, void* arg);
bool selectable_try_write(kselectable* st, result_callback result, buffer_callback buffer, void* arg);
bool selectable_readhup(kselectable* st, result_callback result, void* arg);
void selectable_remove_readhup(kselectable* st);


void selectable_shutdown(kselectable* st);
INLINE void selectable_clear_flags(kselectable* st, uint16_t flags) {
	KBIT_CLR(st->st_flags, flags);
}
INLINE void selectable_bind(kselectable* st, kselector* selector) {
	kgl_selector_module.bind(selector, st);
}
INLINE bool is_selectable(kselectable* st, uint16_t flags) {
	return KBIT_TEST(st->st_flags, flags) > 0;
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
void selectable_udp_read_event(kselectable* st);
void selectable_read_event(kselectable* st);
void selectable_write_event(kselectable* st);
kev_result selectable_event_read(kselectable* st, result_callback result, buffer_callback buffer, void* arg);
kev_result selectable_event_write(kselectable* st, result_callback result, buffer_callback buffer, void* arg);
kev_result selectable_event_sendfile(kselectable* st, result_callback result, buffer_callback buffer, void* arg);
#ifdef ENABLE_KSSL_BIO
void selectable_low_event_read(kselectable* st, result_callback result, buffer_callback buffer, void* arg);
void selectable_low_event_write(kselectable* st, result_callback result, buffer_callback buffer, void* arg);
#endif
#ifndef _WIN32
int selectable_recvmsg(kselectable* st);
#endif
KEND_DECLS
#endif

#ifndef KFIBER_INTERNAL_H
#define KFIBER_INTERNAL_H
#include "kfeature.h"
#include "kforwin32.h"
#include "klist.h"

#ifdef ENABLE_FCONTEXT
#include "fcontext.h"
typedef fcontext_t kfiber_context;
#else
#ifdef _WIN32
#define ENABLE_WIN_FIBER 1
#define kfiber_context void*
#else
#ifdef ENABLE_LIBUCONTEXT
#include "libucontext/libucontext.h"
#define kfiber_context libucontext_ucontext_t
#define kfiber_swapcontext libucontext_swapcontext
#define kfiber_getcontext  libucontext_getcontext
#define kfiber_setcontext libucontext_setcontext
#define kfiber_makecontext libucontext_makecontext
#else
#include <ucontext.h>
#define kfiber_context ucontext_t
#define kfiber_swapcontext swapcontext
#define kfiber_getcontext  getcontext
#define kfiber_setcontext  setcontext
#define kfiber_makecontext makecontext
#endif
#endif
#endif
#define KFIBER_WAITED
KBEGIN_DECLS
//#define switch_main __kfiber_wait
//#define switch_fiber kfiber_wakeup
#ifndef NDEBUG
#define CHECK_FIBER(fiber) do { \
	assert(fiber && !kfiber_is_main_fiber(fiber));\
	assert(fiber->wait_notice_flag == 0);\
}while(0)
#else
#define CHECK_FIBER(fiber)
#endif
typedef struct _kfiber kfiber;
typedef struct _kfiber_mutex kfiber_mutex;
typedef struct _kfiber_rwlock kfiber_rwlock;
typedef struct _kfiber_cond kfiber_cond;
typedef struct _kfiber_chan kfiber_chan;
typedef struct kselector_s kselector;
typedef struct kgl_base_selectable_s kgl_base_selectable;
typedef kgl_base_selectable  kfiber_waiter;

typedef int(*kfiber_start_func)(void* arg, int len);

typedef struct
{
	void* arg;
	result_callback result;
	kgl_iovec* buffer;
#ifdef _WIN32
	WSAOVERLAPPED lp;
#endif
#ifdef LINUX_IOURING
	kselectable* st;
#endif
} kgl_event;

struct kgl_base_selectable_s {
	union {
		kgl_list queue;
		struct {
			/* used by kfiber waiter */
			KOPAQUE wait_obj;
			kgl_base_selectable* next;
		};
	};
	kselector* selector;
	uint32_t st_flags;
	union {
		struct {
			/* used by kselectable */
			uint16_t tmo_left;
			uint16_t tmo;
		};
		/* used by kfiber */
		volatile uint32_t ref;
	};
};

typedef struct _kfiber_cond_function {
	int (*notice)(kfiber_cond* fc,int got);
	int (*wait)(kfiber_cond* fc, int *got);
	int (*try_wait)(kfiber_cond* fc,int* got);
	kev_result(*wait_callback)(kfiber_cond* fc, KOPAQUE data, result_callback notice, void* arg);
	void (*release)(kfiber_cond* fc);
} kfiber_cond_function;

struct _kfiber_cond {
	kfiber_cond_function* f;
	kfiber_waiter* waiter;
	volatile int32_t ev;
};
typedef struct _kfiber_event_waiter {
	kgl_base_selectable base;
	result_callback result;
	void* arg;
} kfiber_event_waiter;

struct _kfiber_chan {
	kfiber_waiter* waiter;
	volatile uint32_t ref;
	int8_t wait_flag;
	volatile uint8_t closed;
};

struct _kfiber {
	kgl_base_selectable base;	/* must at begin */
	kfiber_context ctx;
	//when a fiber exit/wait/yield will switch back to switch_from
	//when a fiber wakeup will set self to target fiber->switch_from
	kfiber * switch_from;
	kfiber_cond * close_cond;
	union {
		kfiber_start_func start;         /* The start function of the thread */
		result_callback cb;
	};
	union {
		int int_arg;
		void* arg;
	};
	union {
		int start_arg;
		int retval;
	};
#ifndef NDEBUG
	union {
		struct {
			uint8_t wait_flag : 1;
			uint8_t notice_flag : 1;
		};
		uint8_t wait_notice_flag;
	};
#endif
#ifndef NDEBUG
	void* wait_code;//wait/wakeup be same.
#endif
#ifndef NDEBUG
	//TRACEBACK sp;
#endif
};
kev_result kfiber_result_callback(KOPAQUE data, void* arg, int got);
int kfiber_buffer_callback(KOPAQUE data, void* arg, WSABUF * buf, int bc);
INLINE bool kfiber_is_main_fiber(kfiber* fiber) {
	return fiber->switch_from == NULL;
}
KEND_DECLS
#endif

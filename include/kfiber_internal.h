#ifndef KFIBER_INTERNAL_H
#define KFIBER_INTERNAL_H
#include "kselector.h"
#ifdef _WIN32
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

#define KFIBER_WAITED
KBEGIN_DECLS
//#define switch_main __kfiber_wait
//#define switch_fiber kfiber_wakeup
#ifndef NDEBUG
#define CHECK_FIBER(fiber) do { \
	if (fiber==NULL || is_main_fiber(fiber)) { \
		assert(false);\
		return -1;\
	}\
	fiber->wait_notice_flag = 0;\
}while(0)
#else
#define CHECK_FIBER(fiber) do { \
	if (fiber==NULL || is_main_fiber(fiber)) { \
		return -1;\
	}\
}while(0)
#endif

typedef struct _kfiber_mutex kfiber_mutex;
typedef struct _kfiber_rwlock kfiber_rwlock;
typedef struct _kfiber_waiter kfiber_waiter;
typedef struct _kfiber_cond kfiber_cond;

typedef struct _kfiber_cond_function {
	int (*notice)(kfiber_cond* fc,int got);
	int (*wait)(kfiber_cond* fc);
	kev_result(*wait_callback)(kfiber_cond* fc, KOPAQUE data, result_callback notice, void* arg);
	void (*release)(kfiber_cond* fc);
} kfiber_cond_function;

struct _kfiber_cond {
	kfiber_cond_function* f;
	kfiber_waiter* waiter;
	volatile int32_t ev;
};

struct _kfiber_waiter {
	kselector* selector;
	result_callback notice;
	KOPAQUE data;
	void* arg;
	kfiber_waiter* next;
};
struct _kfiber {
	kgl_list queue;
	kselector* selector;
	uint16_t st_flags;//always set STF_FIBER
	/////////以上三个必须和kselectable相同
	uint16_t stk_page;
	union {
		volatile int start_arg;
		volatile int retval;
	};
	volatile int32_t ref;
	volatile uint8_t start_called;
#ifndef NDEBUG
	union {
		struct {
			uint8_t wait_flag : 1;
			uint8_t notice_flag : 1;
		};
		uint8_t wait_notice_flag;
	};
#endif
	uint16_t reserve;
	void *wait_code;//wait/wakeup be same.
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
#ifndef NDEBUG
	//TRACEBACK sp;
#endif
#ifndef _WIN32
	void* stack;
#endif
	kfiber_context ctx;
};

#define kfiber_wakeup_waiter(waiter,got) kgl_selector_module.next(waiter->selector, waiter->data, waiter->notice, waiter->arg, got)
INLINE void kfiber_wakeup_all_waiter(kfiber_waiter* waiter,int got)
{
	while (waiter) {
		kfiber_waiter* next = waiter->next;
		kfiber_wakeup_waiter(waiter,got);
		free(waiter);
		waiter = next;
	}
}
void kfiber_add_waiter(kfiber_waiter** head, kselector* selector, KOPAQUE data, result_callback notice, void* arg);
kev_result result_switch_fiber(KOPAQUE data, void* arg, int got);
bool is_main_fiber(kfiber* fiber);
KEND_DECLS
#endif

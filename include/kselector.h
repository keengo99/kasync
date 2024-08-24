#ifndef MSOCKET_SELECTOR_H
#define MSOCKET_SELECTOR_H
#include <assert.h>
#include "kfeature.h"
#include "kforwin32.h"
#include "krbtree.h"
#include "klist.h"
#include "kfiber_internal.h"
#ifndef _WIN32
#include <pthread.h>
#endif
#define KGL_LIST_CONNECT          0
#define KGL_LIST_RW               1
#define KGL_LIST_READY            2
#define KGL_LIST_COUNT            3

#define OP_READ  0
#define OP_WRITE 1
#define SELECTOR_TMO_MSEC 100

KBEGIN_DECLS


typedef struct kserver_selectable_s kserver_selectable;

typedef struct kselectable_s kselectable;
typedef struct kasync_file_s kasync_file;
typedef struct kselector_tick_s kselector_tick;

typedef int (*kselector_tick_callback)(void* arg, int event_count);
typedef kev_result(*aio_callback)(kasync_file* fp, void* arg, char* buf, int length);


typedef void (*selector_init)(kselector* selector);
typedef bool (*selector_listen)(kserver_selectable* st, result_callback result);
typedef bool (*selector_accept)(kserver_selectable* st, void* arg);
typedef void (*selector_bind)(kselector* selector, kselectable* st);

typedef void (*selector_remove)(kselector* selector, kselectable* st);
typedef bool (*selector_read)(kselector* selector, kselectable* st, result_callback result, kgl_iovec* buffer, void* arg);
typedef bool (*selector_readhup)(kselector* selector, kselectable* st, result_callback result, void* arg);
typedef bool (*selector_remove_readhup)(kselector* selector, kselectable* st);

typedef bool (*selector_write)(kselector* selector, kselectable* st, result_callback result, kgl_iovec* buffer, void* arg);
typedef bool (*selector_connect)(kselector* selector, kselectable* st, result_callback result, void* arg);

typedef void (*selector_next)(kselector* selector, KOPAQUE data, result_callback result, void* arg, int got);

typedef void (*selector_aio_open)(kselector* selector, kasync_file* file, FILE_HANDLE fd);
typedef bool (*selector_aio_write)(kasync_file* file, result_callback result, const char *buf, int length, void* arg);
typedef bool (*selector_aio_read)(kasync_file* file, result_callback result, char *buf, int length, void* arg);
typedef bool (*selector_sendfile)(kselectable* st, result_callback result, kgl_iovec* buffer, void* arg);
/* tmo is millisecond */
typedef int  (*selector_select)(kselector* selector, int tmo);
typedef void (*selector_destroy)(kselector* selector);

typedef struct kconnection_s kconnection;
typedef struct kselector_notice_s kselector_notice;

struct kselector_notice_s
{
	result_callback result;
	KOPAQUE data;
	void* arg;
	int got;
	kselector_notice* next;
};

typedef struct kgl_block_queue_s kgl_block_queue;
struct kgl_block_queue_s
{
	KOPAQUE data;
	void* arg;
	result_callback func;
	int64_t active_msec;
	kgl_block_queue* next;
};

typedef struct
{
	const char* name;

	selector_init init;
	selector_destroy destroy;
	selector_bind bind;

	selector_listen listen;
	selector_accept accept;
	selector_connect connect;

	selector_remove remove;
	selector_read read;
	selector_write write;
	selector_readhup readhup;
	selector_remove_readhup remove_readhup;

	selector_select select;
	selector_next next;

	/* aio file */
	selector_aio_open aio_open;
	selector_aio_write aio_write;
	selector_aio_read aio_read;
	selector_sendfile sendfile;

} kselector_module;

struct kselector_s
{
	void* ctx;
	int sid;
	volatile int count;
	uint32_t utm : 1;
	uint32_t aysnc_main : 1;
	volatile uint32_t closed : 1;
	volatile uint32_t shutdown : 1;
	volatile int ret_val;
	int timeout[KGL_LIST_COUNT];
	kgl_list list[KGL_LIST_COUNT];
	kgl_list tick;
	struct krb_root block;
	struct krb_node* block_first;
	kfiber* current;
#ifdef MALLOCDEBUG
	volatile
#endif
		pthread_t thread_id;

};
kselector* kselector_new(kselector_tick* tick);
void kselector_destroy(kselector* selector);
bool kselector_start(kselector* selector);
KTHREAD_FUNCTION kselector_thread(void* param);
bool kselector_is_same_thread(kselector* selector);
void kselector_add_list(kselector* selector, kselectable* st, int list);
void kselector_add_fiber_ready(kselector* selector, kfiber* fiber);
void kselector_remove_list(kselector* selector, kselectable* st);
void kselector_update_time();
int kselector_check_timeout(kselector* selector, int event_number);
int kselector_add_timer(kselector* selector, result_callback result, void* arg, int msec, KOPAQUE data);
void kselector_adjust_time(kselector* selector, int64_t diff_time);
void kselector_default_bind(kselector* selector, kselectable* st);
bool kselector_default_readhup(kselector* selector, kselectable* st, result_callback result, void* arg);
bool kselector_default_remove_readhup(kselector* selector, kselectable* st);
void kselector_default_remove(kselector* selector, kselectable* st);
bool kselector_not_support_sendfile(kselector* selector, kselectable* st);

kselector_tick* kselector_new_tick(kselector_tick_callback cb, void* arg);
bool kselector_register_tick(kselector_tick* tick);
bool kselector_close_tick(kselector_tick* tick);

kev_result kselector_event_accept(KOPAQUE data, void* arg, int got);
INLINE bool kselector_can_close(kselector* selector) {
	return (selector->closed && selector->count == 0 && selector->block.rb_node == NULL);
}
extern pthread_key_t kgl_selector_key;
INLINE kselector* kgl_get_tls_selector() {
	return (kselector*)pthread_getspecific(kgl_selector_key);
}
INLINE kfiber* kselector_get_fiber(kselector* selector) {
	assert(kgl_get_tls_selector() == selector);
	assert(selector->current == NULL || selector->current->base.selector == selector);
	return (kfiber*)selector->current;
}
INLINE void kselector_set_fiber(kselector* selector, kfiber* fiber) {
	assert(fiber->base.selector == selector);
	assert(kgl_get_tls_selector() == selector);
	selector->current = fiber;
}
extern kselector_module kgl_selector_module;
extern volatile int64_t kgl_current_msec;
extern volatile time_t kgl_current_sec;
extern time_t kgl_program_start_sec;
KEND_DECLS
#endif

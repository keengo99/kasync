#ifndef MSOCKET_SELECTOR_H
#define MSOCKET_SELECTOR_H
#include "kfeature.h"
#include "kforwin32.h"
#include "krbtree.h"
#include "klist.h"
#ifndef _WIN32
#include <pthread.h>
#endif
#define KGL_LIST_CONNECT          0
#define KGL_LIST_RW               1
#define KGL_LIST_SYNC             2
#define KGL_LIST_READY            3
#define KGL_LIST_BLOCK            4
#define KGL_LIST_NONE             5
#define OP_READ  0
#define OP_WRITE 1
#define SELECTOR_TMO_MSEC 100
KBEGIN_DECLS
typedef int(*kfiber_start_func)(void* arg, int len);
typedef struct _kfiber kfiber;
typedef struct kserver_selectable_s kserver_selectable;
typedef struct kselector_s kselector;
typedef struct kselectable_s kselectable;
typedef struct kasync_file_s kasync_file;


typedef void (*selector_check_timeout_callback)(kselector *selector, int event_count);
typedef kev_result (*aio_callback)(kasync_file *fp, void *arg, char *buf, int length);


typedef void (*selector_init)(kselector *selector);
typedef bool (*selector_listen)(kselector *selector, kserver_selectable *st, result_callback result);
typedef bool (*selector_accept)(kselector* selector, kserver_selectable* st, void *arg);
typedef void (*selector_bind)(kselector *selector, kselectable *st);

typedef void (*selector_remove)(kselector *selector,kselectable *st);
typedef bool (*selector_read)(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, void *arg);
typedef bool (*selector_readhup)(kselector *selector, kselectable *st, result_callback result, void *arg);
typedef bool (*selector_remove_readhup)(kselector *selector, kselectable *st);

typedef bool (*selector_write)(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, void *arg);
typedef bool (*selector_connect)(kselector *selector, kselectable *st, result_callback result, void *arg);
typedef bool (*selector_recvfrom)(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, buffer_callback addr_buffer, void *arg);
typedef void (*selector_next)(kselector *selector, KOPAQUE data, result_callback result, void *arg, int got);

typedef void (*selector_aio_open)(kselector *selector, kasync_file *file, FILE_HANDLE fd);
typedef bool (*selector_aio_write)(kselector *selector, kasync_file *file, char *buf, int64_t offset, int length, aio_callback cb, void *arg);
typedef bool (*selector_aio_read)(kselector *selector, kasync_file *file, char *buf, int64_t offset, int length, aio_callback cb, void *arg);

typedef int  (*selector_select)(kselector *selector);
typedef void (*selector_destroy)(kselector *selector);

typedef struct kconnection_s kconnection;
typedef struct kselector_notice_s kselector_notice;

struct kselector_notice_s
{
	result_callback result;
	KOPAQUE data;
	void *arg;
	int got;
	kselector_notice *next;
};

typedef struct kgl_block_queue_s kgl_block_queue;
struct kgl_block_queue_s
{
	kselectable *st;
	void *arg;
	result_callback func;
	int got;
	int64_t active_msec;
	kgl_block_queue *next;
};

typedef struct {
	const char *name;

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
	selector_recvfrom recvfrom;

	selector_select select;
	selector_next next;

	selector_aio_open aio_open;
	selector_aio_write aio_write;
	selector_aio_read aio_read;

} kselector_module;

struct kselector_s {
	void *ctx;
	int sid;
	volatile int count;
	uint32_t utm : 1;
	uint32_t aysnc_main : 1;
	volatile uint32_t closed : 1;
	volatile uint32_t shutdown : 1;
	int timeout[KGL_LIST_BLOCK];
	kgl_list list[KGL_LIST_BLOCK];
	struct krb_root block;
	struct krb_node *block_first;
	selector_check_timeout_callback check_timeout;
#ifdef MALLOCDEBUG
	volatile
#endif
	pthread_t thread_id;
	volatile int ret_val;
};
kselector *kselector_new();
void kselector_destroy(kselector *selector);
bool kselector_start(kselector *selector);
KTHREAD_FUNCTION kselector_thread(void *param);
bool kselector_is_same_thread(kselector *selector);
void kselector_add_list(kselector *selector,kselectable *st, int list);
void kselector_add_fiber_ready(kselector* selector, kfiber* fiber);
void kselector_remove_list(kselector *selector, kselectable *st);
void kselector_update_time();
void kselector_check_timeout(kselector *selector,int event_number);
void kselector_add_timer(kselector *selector, result_callback result, void *arg, int msec,kselectable *st);
void kselector_adjust_time(kselector *selector,int64_t diff_time);
void kselector_default_bind(kselector *selector, kselectable *st);
bool kselector_default_readhup(kselector *selector, kselectable *st, result_callback result,  void *arg);
bool kselector_default_remove_readhup(kselector *selector, kselectable *st);
void kselector_default_remove(kselector *selector, kselectable *st);
kev_result kselector_event_accept(KOPAQUE data, void *arg,int got);
INLINE bool kselector_can_close(kselector *selector)
{
	return (selector->closed && selector->count == 0 && selector->block.rb_node == NULL);
}
extern pthread_key_t kgl_selector_key;
INLINE kselector *kgl_get_tls_selector()
{
	return (kselector *)pthread_getspecific(kgl_selector_key);
}
extern kselector_module kgl_selector_module;
extern volatile int64_t kgl_current_msec;
extern volatile time_t kgl_current_sec;
extern time_t kgl_program_start_sec;
extern volatile uint32_t kgl_aio_count;
KEND_DECLS
#endif

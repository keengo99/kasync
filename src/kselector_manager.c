#include <assert.h>
#include "kselector_manager.h"
#include "kselector.h"
#include "klib.h"
#include "kmalloc.h"
#include "kthread.h"
#include "ksync.h"
#include "klog.h"
#include "kfiber.h"
#include "kaddr.h"
#include "kfiber_sync.h"
#ifdef _WIN32
#include "kiocp_selector.h"
#else
#include <signal.h>
#endif

#ifdef LINUX
#ifdef LINUX_IOURING
#include "kiouring_selector.h"
#endif
#include "kepoll_selector.h"
#endif
#ifdef BSD_OS
#include "kkqueue_selector.h"
#endif
#include <stdio.h>
#define KTHREAD_FLUSH_TIMER 60000
static kselector **kgl_selectors = NULL;
static int kgl_selector_count = 0;
static unsigned kgl_selector_hash = 0;
static unsigned kgl_selector_index = 0;

typedef struct {
	void *ctx;
	selectable_iterator it;
	kfiber_cond *cond;
} selectable_iterator_param;

typedef struct kgl_selector_manager_callback_s kgl_selector_manager_callback;
struct kgl_selector_manager_callback_s
{
	result_callback call_back;
	void *arg;
	kgl_selector_manager_callback *next;
};
static kgl_selector_manager_callback *on_ready_list = NULL;
static kgl_selector_manager_callback *thread_init = NULL;
extern void(*kgl_second_change_hook)();
void kselector_init(kselector* selector)
{
	srand((unsigned)(time(NULL) * (int64_t)pthread_self()));
	pthread_setspecific(kgl_selector_key, selector);
	selector->thread_id = pthread_self();
	kgl_selector_manager_callback* cb = thread_init;
	while (cb) {
		cb->call_back(NULL, cb->arg, 0);
		cb = cb->next;
	}
}
void kselector_exit(kselector* selector)
{
	kgl_selector_manager_callback* cb = thread_init;
	while (cb) {
		cb->call_back(NULL, cb->arg, 1);
		cb = cb->next;
	}
	pthread_setspecific(kgl_selector_key, NULL);
	klog(KLOG_ERR, "selector thread = [%d] now close.\n", selector->thread_id);
	selector->thread_id = 0;
}
void kselector_step_init(int index)
{
	kselector* selector = kgl_selectors[index];
	assert(selector != NULL);
	kselector_init(selector);
}
int kselector_step(int index)
{
	kselector* selector = kgl_selectors[index];
	assert(selector == kgl_get_tls_selector());
	assert(selector != NULL);
	kselector_check_timeout(selector, 1);
	return kgl_selector_module.select(selector);
}
void kselector_step_exit(int index)
{
	kselector* selector = kgl_selectors[index];
	assert(selector == kgl_get_tls_selector());
	kselector_exit(selector);
}
KTHREAD_FUNCTION kselector_thread(void *param)
{
	kselector *selector = (kselector*)param;
	kselector_init(selector);
	int ret = 0;
	for (;;) {
#ifdef MALLOCDEBUG
		if (kselector_can_close(selector)) {
			break;
		}
#endif
		kselector_check_timeout(selector, ret);
		ret = kgl_selector_module.select(selector);
	}
	kselector_exit(selector);
	KTHREAD_RETURN;
}
void kselector_add_block_queue(kselector *selector, kgl_block_queue *bq);
static kev_result next_add_timer(KOPAQUE data, void *arg, int got)
{
	kgl_block_queue *brq = (kgl_block_queue *)arg;
	kselector_add_block_queue(kgl_get_tls_selector(),brq);
	return kev_ok;
}
static kev_result add_timer_on_ready(KOPAQUE data, void* arg, int got)
{
	kgl_block_queue *brq = (kgl_block_queue *)arg;
	kselector *selector = get_perfect_selector();
	kgl_selector_module.next(selector,NULL, next_add_timer, brq,0);
	return kev_ok;
}
static kev_result selector_iterator(KOPAQUE data, void *arg, int got)
{
	selectable_iterator_param *param = (selectable_iterator_param *)arg;
	kselector *selector = kgl_get_tls_selector();
	struct krb_node *node = selector->block_first;
	for (int i = 0; i < KGL_LIST_BLOCK; i++) {
		kgl_list *l;
		klist_foreach(l, &selector->list[i]) {
			kselectable *st = (kselectable *)kgl_list_data(l, kselectable, queue);
			if (!param->it(param->ctx, selector, st)) {
				goto done;
			}
		}
	}
	while (node) {
		kgl_block_queue *brq = (kgl_block_queue *)node->data;
		while (brq) {
			if (brq->st) {
				if (!param->it(param->ctx, selector, brq->st)) {
					goto done;
				}
			}
			brq = brq->next;
		}
		node = rb_next(node);
	}
done:
	param->cond->f->notice(param->cond, got);
	return kev_ok;
}
void selector_manager_iterator(void *ctx, selectable_iterator it)
{
	selectable_iterator_param param;
	param.ctx = ctx;
	param.it = it;
	param.cond = kfiber_cond_init_ts(true);
	for (int i = 0; i < kgl_selector_count; i++) {
		kselector *selector = kgl_selectors[i];
		kgl_selector_module.next(selector, NULL, selector_iterator, &param, 0);
		param.cond->f->wait(param.cond);
	}
	param.cond->f->release(param.cond);
}
void selector_manager_add_timer(result_callback timer, void *arg, int msec, kselectable *st)
{
	kgl_block_queue *brq = xmemory_new(kgl_block_queue);
	brq->active_msec = kgl_current_msec + msec;
	brq->func = timer;
	brq->arg = arg;
	brq->st = st;
	if (is_selector_manager_init()) {
		kgl_selector_module.next(get_perfect_selector(), NULL, next_add_timer, brq, 0);
		return;
	}
	selector_manager_on_ready(add_timer_on_ready, brq);
}
void kselector_add_timer_ts(kselector *selector,result_callback timer, void *arg, int msec, kselectable *st)
{
	kgl_block_queue *brq = xmemory_new(kgl_block_queue);
	brq->active_msec = kgl_current_msec + msec;
	brq->func = timer;
	brq->arg = arg;
	brq->st = st;
	kassert(is_selector_manager_init());
	if (kselector_is_same_thread(selector)) {
		kselector_add_block_queue(selector, brq);
		return;
	}
	kgl_selector_module.next(selector, NULL, next_add_timer, brq, 0);		
}
int get_selector_count()
{
	return kgl_selector_count;
}
void selector_manager_close()
{
	for (int i = 0; i < kgl_selector_count; i++) {
		kgl_selectors[i]->shutdown = 1;
	}
	sleep(1);
	for (int i = 0; i < kgl_selector_count; i++) {
		kgl_selectors[i]->closed = 1;
	}
	for (int i = 0; i < kgl_selector_count; i++) {
		kselector *selector = kgl_selectors[i];
		for (;;) {
			if (selector->thread_id == 0) {
				kselector_destroy(selector);
				break;
			}
			sleep(1);
		}
	}
	xfree(kgl_selectors);
}
void selector_manager_start(void(*time_hook)(),bool thread)
{
	kgl_second_change_hook = time_hook;
	kgl_program_start_sec = kgl_current_sec;
	for (int i = 1; i < kgl_selector_count; i++) {
		kselector_start(kgl_selectors[i]);
	}
	if (thread) {
		kselector_start(kgl_selectors[0]);
	} else {
		kselector_thread(kgl_selectors[0]);
	}
}
void selector_manager_adjust_time(int64_t diff_msec)
{
	klog(KLOG_ERR, "WARNING!! adjust system time diff_msec=[" INT64_FORMAT "]\n",diff_msec);
	kgl_program_start_sec += (diff_msec / 1000);
	for (int i = 0; i < kgl_selector_count; i++) {
		kselector_adjust_time(kgl_selectors[i], diff_msec);
	}
}
static kev_result kthread_flush_timer(KOPAQUE data, void *arg, int got)
{
	kselector *selector = (kselector *)arg;
	kthread_flush(0);
	kselector_add_timer(selector, kthread_flush_timer, selector, KTHREAD_FLUSH_TIMER, NULL);
	return kev_ok;
}
void selector_module_create()
{
#if defined(_WIN32)
	kiocp_module_init();
#elif defined(LINUX_IOURING)
	if (!kiouring_is_support()) {
		fprintf(stderr,"io_uring not satisfaction.\n");
		abort();
	}
	kiouring_module_init();
#elif defined(LINUX_EPOLL)
	kepoll_module_init();
#elif defined(BSD_OS)
	kkqueue_module_init();
#else
#error no selector module init
#endif
}
static void selector_manager_add_callback(kgl_selector_manager_callback **list, result_callback call_back, void *arg)
{
	kgl_selector_manager_callback *item = (kgl_selector_manager_callback *)malloc(sizeof(kgl_selector_manager_callback));
	item->call_back = call_back;
	item->arg = arg;
	item->next = *list;
	*list = item;
}
void selector_manager_thread_init(result_callback call_back, void *arg)
{
	selector_manager_add_callback(&thread_init, call_back, arg);
}
void selector_manager_init(unsigned  size, bool register_thread_timer)
{
	if (kgl_selector_module.name == NULL) {
		kselector_update_time();
		pthread_key_create(&kgl_selector_key, NULL);
		selector_module_create();
		if (kgl_selector_module.name == NULL) {
			fprintf(stderr, "kgl_selector_module init failed. forget call kasync_init?\n");
			abort();
		}
	}
	int i;
	for (i = 0; i < 7; i++) {
		kgl_selector_count = (1 << i);
		if (kgl_selector_count == (int)size) {
			break;
		}
		if (kgl_selector_count > (int)size) {
			kgl_selector_count--;
			break;
		}
	}
	kgl_selector_hash = kgl_selector_count - 1;
	kgl_selectors = (kselector **)xmalloc(sizeof(kselector *)*kgl_selector_count);
	for (i = 0; i < kgl_selector_count; i++) {
		kgl_selectors[i] = kselector_new();
		if (i == 0) {
			kgl_selectors[i]->utm = 1;
		}
		kgl_selectors[i]->sid = i;
	}
	selector_manager_set_timeout(10, 30);
	//call onReadyList
	while (on_ready_list) {
		kgl_selector_module.next(get_perfect_selector(), NULL, on_ready_list->call_back, on_ready_list->arg, 0);
		kgl_selector_manager_callback *next = on_ready_list->next;
		free(on_ready_list);
		on_ready_list = next;
	}
	if (register_thread_timer) {
		kselector *selector = get_perfect_selector();
		selector_manager_add_timer(kthread_flush_timer, selector, KTHREAD_FLUSH_TIMER, NULL);
	}
}
static void selector_set_time_out(int time_out_index, int msec)
{
	if (msec <= 0) {
		msec = 60000;
	}
	int i;
	for (i = 0; i < kgl_selector_count; i++) {
		kgl_selectors[i]->timeout[time_out_index] = msec;
	}
}
void selector_manager_set_timeout(int connect_tmo_sec, int rw_tmo_sec)
{
	if (connect_tmo_sec <= 0) {
		connect_tmo_sec = rw_tmo_sec;
	}
	selector_set_time_out(KGL_LIST_CONNECT, connect_tmo_sec * 1000);
	selector_set_time_out(KGL_LIST_RW, rw_tmo_sec * 1000);

}

void selector_manager_on_ready(result_callback call_back, void *arg)
{
	if (is_selector_manager_init()) {
		kgl_selector_module.next(get_perfect_selector(), NULL, call_back, arg, 0);
		return;
	}
	selector_manager_add_callback(&on_ready_list, call_back, arg);
}
bool is_selector_manager_init()
{
	return kgl_selectors != NULL;
}
kselector *get_selector_by_index(int index)
{
	return kgl_selectors[index & kgl_selector_hash];
}
kselector *get_perfect_selector()
{
	unsigned i = kgl_selector_index;
	for (int j = 0; j < kgl_selector_count; j++, i++) {
		kselector *selector = kgl_selectors[i & kgl_selector_hash];
		kselector *next_selector = kgl_selectors[(i + 1) & kgl_selector_hash];
		if (selector->count < next_selector->count + 64) {
			kgl_selector_index = i + 1;
			return selector;
		}
	}
	kassert(false);
	return get_selector_by_index(kgl_selector_index++);
}
const char *selector_manager_event_name()
{
	return kgl_selector_module.name;
}
int kasync_fiber_main(void* arg, int argc)
{
	void** args = (void**)arg;
	kfiber_start_func main_func = (kfiber_start_func)args[0];
	int ret = main_func(args[1], argc);
	kselector * selector = kgl_get_tls_selector();
	assert(selector);
	selector->closed = 1;
	selector->ret_val = ret;
	return 0;
}
void kasync_init()
{
	if (kgl_selector_module.name) {
		return;
	}
#ifndef _WIN32
	signal(SIGPIPE,SIG_IGN);
#endif	
	ksocket_startup();
	kselector_update_time();
	pthread_key_create(&kgl_selector_key, NULL);
	selector_module_create();
	kthread_init();
	kfiber_init();
	kgl_addr_init();
#ifdef KSOCKET_SSL
	kssl_init2();
#endif
}
int kasync_main(kfiber_start_func main, void* arg, int argc)
{
	kasync_init();
	kselector* selector = kselector_new();
	selector->aysnc_main = 1;
	void* args[2];
	args[0] = (void*)main;
	args[1] = arg;
	kselector_init(selector);
	kfiber_create2(selector, kasync_fiber_main, (void*)args, argc, 0, NULL);
	selector->utm = 1;
	for (;;) {
		kselector_check_timeout(selector, kgl_selector_module.select(selector));
		if (selector->closed) {
			assert(kselector_can_close(selector));
			assert(klist_empty(&selector->list[KGL_LIST_READY]));
			break;
		}
	}
	int ret_val = selector->ret_val;
	kselector_exit(selector);
	kselector_destroy(selector);
	return ret_val;
}


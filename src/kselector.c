#include <time.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#ifndef _WIN32
#include <sys/time.h>
#endif
#include "kselector.h"
#include "kselectable.h"
#include "kthread.h"
#include "kselector_manager.h"
#include "klog.h"
#include "kmalloc.h"
#include "kfiber.h"
pthread_key_t kgl_selector_key;
kselector_module kgl_selector_module = { NULL };
volatile int64_t kgl_current_msec = 0;
volatile time_t kgl_current_sec = 0;
time_t kgl_program_start_sec = 0;
void (*kgl_second_change_hook)() = NULL;
KTHREAD_FUNCTION kselector_thread(void *param);
struct kselector_tick_s
{
	kgl_list queue;
	void* arg;
	kselector_tick_callback cb;
};
typedef union _kgl_ready_event {
	kselectable st;
	kfiber fiber;
	kgl_base_selectable base;
} kgl_ready_event;

#ifdef WIN32
static inline int gettimeofday(struct timeval *tp, void *tzp)
{
	time_t clock;
	struct tm tm;
	SYSTEMTIME wtm;
	GetLocalTime(&wtm);
	tm.tm_year = wtm.wYear - 1900;
	tm.tm_mon = wtm.wMonth - 1;
	tm.tm_mday = wtm.wDay;
	tm.tm_hour = wtm.wHour;
	tm.tm_min = wtm.wMinute;
	tm.tm_sec = wtm.wSecond;
	tm.tm_isdst = -1;
	clock = mktime(&tm);
	tp->tv_sec = (long)clock;
	tp->tv_usec = wtm.wMilliseconds * 1000;
	return (0);
}
#endif
static kev_result next_adjust_time(KOPAQUE data, void *arg, int got)
{
	int64_t *diff_time = (int64_t *)arg;
	kselector_adjust_time(kgl_get_tls_selector(), *diff_time);
	xfree(diff_time);
	return kev_ok;
}
static INLINE struct krb_node *kgl_insert_block_queue(struct krb_root *root, kgl_block_queue *brq, bool *is_first)
{
	struct krb_node **n = &(root->rb_node), *parent = NULL;
	kgl_block_queue *tmp = NULL;
	while (*n) {
		tmp = (kgl_block_queue *)((*n)->data);
		int64_t result = brq->active_msec - tmp->active_msec;
		parent = *n;
		if (result < 0) {
			n = &((*n)->rb_left);
		} else if (result > 0) {
			n = &((*n)->rb_right);
			*is_first = false;
		} else {
			*is_first = false;
			brq->next = tmp;
			(*n)->data = brq;
			return *n;
		}
	}
	struct krb_node *node = (struct krb_node *)xmalloc(sizeof(struct krb_node));
	node->data = brq;
	brq->next = NULL;
	rb_link_node(node, parent, n);
	rb_insert_color(node, root);
	return node;
}

bool kselector_is_same_thread(kselector *selector)
{
	return pthread_self() == selector->thread_id;
}
void kselector_destroy(kselector *selector)
{
	kgl_selector_module.destroy(selector);
	xfree(selector);
}
kselector *kselector_new(kselector_tick *tick)
{
	kselector *selector = (kselector *)xmalloc(sizeof(kselector));
	memset(selector, 0, sizeof(kselector));
	selector->sid = -1;
	for (int i = 0; i < KGL_LIST_COUNT; i++) {
		klist_init(&selector->list[i]);
		selector->timeout[i] = 60 * 1000;
	}
	klist_init(&selector->tick);
	kgl_selector_module.init(selector);
	if (tick) {
		klist_append(&selector->tick, &tick->queue);
	}
	return selector;
}
bool kselector_start(kselector *selector)
{
	return kthread_pool_start(kselector_thread, selector);
}
void kselector_next(kselector *selector, KOPAQUE data, result_callback result, void *arg, int got)
{
	kassert(kselector_is_same_thread(selector));
}
void kselector_adjust_time(kselector *selector, int64_t diff_time)
{
	if (!kselector_is_same_thread(selector)) {
		int64_t *param = xmemory_new(int64_t);
		*param = diff_time;
		kgl_selector_module.next(selector,NULL, next_adjust_time, param,0);
		return;
	}
	struct krb_node *node = selector->block_first;
	while (node) {
		kgl_block_queue *brq = (kgl_block_queue *)node->data;
		kassert(brq);
		brq->active_msec += diff_time;
		node = rb_next(node);
	}
	for (int i = 0; i <= KGL_LIST_RW; i++) {
		kgl_list *pos;
		klist_foreach (pos, &selector->list[i]) {
			kselectable *st = kgl_list_data(pos, kselectable, base.queue);
			st->active_msec += diff_time;
		}
	}
}
void kselector_update_time()
{	
	struct timeval   tv;
	gettimeofday(&tv, NULL);
	if (unlikely(kgl_current_sec != tv.tv_sec)) {
		if (unlikely(tv.tv_sec < kgl_current_sec)) {
			int64_t diff_msec = (int64_t)tv.tv_sec * 1000 + (tv.tv_usec / 1000) - kgl_current_msec;
			selector_manager_adjust_time(diff_msec);
		}		
		kgl_current_sec = tv.tv_sec;
		if (kgl_second_change_hook) {
			kgl_second_change_hook();
		}
	}
	kgl_current_msec = (int64_t)tv.tv_sec * 1000 + (tv.tv_usec / 1000);
	return;
}
int kselector_check_timeout(kselector *selector,int event_number)
{
	kgl_list* tick_list,*tick_next_list;
	kselector_tick* tick;
	struct krb_node *block = NULL;
	struct krb_node *last = NULL;
	int min_event_time = SELECTOR_TMO_MSEC;
	//read write timeout
	for (int i = 0; i <= KGL_LIST_RW; i++) {
		for (;;) {
			kgl_list *l = klist_head(&selector->list[i]);
			if (l == &selector->list[i]) {
				break;
			}
			kselectable *st = kgl_list_data(l, kselectable, base.queue);
			kassert(st->base.selector == selector);
#ifdef MALLOCDEBUG
			if (selector->shutdown) {
				selectable_shutdown(rq);
			}
#endif
			if ((kgl_current_msec - st->active_msec) < (time_t)selector->timeout[i]) {
				break;
			}
			klist_remove(l);
			memset(l, 0, sizeof(kgl_list));
			if (st->base.tmo_left > 0) {
				st->base.tmo_left--;
				st->active_msec = kgl_current_msec;
				klist_append(&selector->list[i], l);
				continue;
			}
			memset(l, 0, sizeof(kgl_list));
#ifndef NDEBUG
			//klog(KLOG_DEBUG, "request timeout st=%p\n", (kselectable *)rq);
#endif
			kassert(selector->count > 0);
			if (KBIT_TEST(st->base.st_flags, STF_RTIME_OUT) && KBIT_TEST(st->base.st_flags,STF_READ)>0) {
				//set read time out
				klist_append(&selector->list[i], l);
				st->active_msec = kgl_current_msec;
				kassert(st->e[OP_READ].result);
				st->e[OP_READ].result(st->data, st->e[OP_READ].arg, ST_ERR_TIME_OUT);
				continue;
			}
			selector->count--;
			selectable_shutdown(st);
		}
	}

	while (selector->block_first) {
		kgl_block_queue *rq = (kgl_block_queue *)selector->block_first->data;
		kassert(rq);
#ifdef MALLOCDEBUG
		if (selector->shutdown) {
			rq->active_msec = kgl_current_msec - 1;
		}
#endif
		if (kgl_current_msec < rq->active_msec) {
			break;
		}
		struct krb_node *next = rb_next(selector->block_first);
		rb_erase(selector->block_first, &selector->block);
		if (last != NULL) {
			last->rb_right = selector->block_first;
		} else {
			block = selector->block_first;
		}
		last = selector->block_first;
		last->rb_right = NULL;
		selector->block_first = next;
	}

	while (block) {
		kgl_block_queue *rq = (kgl_block_queue *)block->data;
		while (rq) {
			kgl_block_queue *rq_next = rq->next;
			rq->func(rq->data,rq->arg, 0);
			xfree(rq);
			rq = rq_next;
		}
		last = block->rb_right;
		xfree(block);
		block = last;
	}
	//handle ready list
	for (;;) {
		kgl_list *l = klist_head(&selector->list[KGL_LIST_READY]);
		if (l == &selector->list[KGL_LIST_READY]) {
			break;
		}
		kgl_ready_event* ready_ev = (kgl_ready_event *)kgl_list_data(l, kgl_base_selectable, queue);
		//printf("ready ev st=[%p] fd=[%d]\n",ready_ev, ready_ev->st.fd);
		kassert(ready_ev->base.selector == selector);
		klist_remove(l);
		memset(l, 0, sizeof(kgl_list));
		selector->count--;
		if (ready_ev->base.st_flags == STF_FIBER) {
			ready_ev->fiber.cb(ready_ev, ready_ev->fiber.arg, ready_ev->fiber.retval);
			continue;
		}
		uint16_t st_flags = ready_ev->st.base.st_flags;
		if (KBIT_TEST(st_flags, STF_WREADY | STF_WREADY2) && KBIT_TEST(st_flags, STF_WRITE | STF_RDHUP)) {
			assert(!KBIT_TEST(st_flags,STF_UDP));
#if 0
			//current udp do not support send event.
			if (unlikely(KBIT_TEST(st_flags, STF_UDP))) {
				selectable_udp_write_event(&ready_ev->st);
			}
#endif
			selectable_write_event(&ready_ev->st);
			KBIT_CLR(st_flags, STF_WRITE | STF_RDHUP);
		}
		if (KBIT_TEST(st_flags, STF_RREADY | STF_RREADY2) && KBIT_TEST(st_flags, STF_READ)) {
			selectable_read_event(&ready_ev->st);
			KBIT_CLR(st_flags, STF_READ);
		}
		if (KBIT_TEST(st_flags, STF_READ | STF_WRITE) &&
#ifdef STF_ET
			KBIT_TEST(st_flags, STF_ET) &&
#endif
			ready_ev->base.queue.next == NULL) {
			kselector_add_list(selector, &ready_ev->st, KGL_LIST_RW);
		}
	}
	tick_list = klist_head(&selector->tick);

	while (tick_list != &selector->tick) {
		tick = kgl_list_data(tick_list, kselector_tick, queue);
		tick_next_list = tick_list->next;
		int next_event_time = tick->cb(tick->arg, event_number);
		if (next_event_time > 0 && next_event_time < min_event_time) {
			min_event_time = next_event_time;
		}
		tick_list = tick_next_list;
	}
	return min_event_time;
}
void kselector_add_block_queue(kselector *selector, kgl_block_queue *brq)
{
	kassert(kselector_is_same_thread(selector));
	bool is_first = true;
	struct krb_node	*node = kgl_insert_block_queue(&selector->block, brq, &is_first);
	if (is_first) {
		selector->block_first = node;
	}
	kassert(selector->block_first == rb_first(&selector->block));
}
int kselector_add_timer(kselector *selector, result_callback result, void *arg, int msec, KOPAQUE data)
{
#ifdef MALLOCDEBUG
	if (selector->shutdown) {
		return -1;
	}
#endif
	kgl_block_queue *brq = (kgl_block_queue *)xmalloc(sizeof(kgl_block_queue));
	memset(brq, 0, sizeof(kgl_block_queue));
	brq->active_msec = kgl_current_msec + msec;
	brq->func = result;
	brq->arg = arg;
	brq->data = data;
	kselector_add_block_queue(selector, brq);
	return 0;
}
void kselector_default_bind(kselector *selector, kselectable *st)
{
	st->base.selector = selector;
}
bool kselector_default_readhup(kselector *selector, kselectable *st, result_callback result,  void *arg)
{
        return false;
}
bool kselector_default_remove_readhup(kselector *selector, kselectable *st)
{
        return false;
}
void kselector_default_remove(kselector *selector, kselectable *st)
{
}
kselector_tick* kselector_new_tick(kselector_tick_callback cb, void* arg)
{
	kselector_tick* tick = (kselector_tick*)xmalloc(sizeof(kselector_tick));
	if (tick == NULL) {
		return NULL;
	}
	tick->arg = arg;
	tick->cb = cb;
	klist_init(&tick->queue);
	return tick;
}
bool kselector_register_tick(kselector_tick *tick)
{
	kselector* selector = kgl_get_tls_selector();
	if (selector == NULL) {
		return false;
	}
	klist_append(&selector->tick, &tick->queue);
	return true;
}
bool kselector_close_tick(kselector_tick* tick)
{
	kselector* selector = kgl_get_tls_selector();
	if (selector == NULL) {
		return false;
	}
	klist_remove(&tick->queue);
	xfree(tick);
	return true;
}
bool kselector_not_support_sendfile(kselector* selector, kselectable* st) {
	return false;
}

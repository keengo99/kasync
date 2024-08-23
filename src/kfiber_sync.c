#include "kfiber_sync.h"
#include "ksync.h"
#include "kfiber_internal.h"
#include "kfiber.h"
#define KFIBER_CHAN_NO_WAITER   0
#define KFIBER_CHAN_RECV_WAITER 1
#define KFIBER_CHAN_SEND_WAITER 2

//mutext
kev_result kfiber_mutex_lock2(kfiber_mutex* mutex, KOPAQUE data, result_callback notice, void* arg)
{
	kassert(kfiber_self() == NULL);
	kmutex_lock(&mutex->lock);
	if (mutex->worker < mutex->limit) {
		mutex->worker++;
		kmutex_unlock(&mutex->lock);
		kgl_selector_module.next(kgl_get_tls_selector(), data, notice, arg, 0);
		return kev_ok;
	}
	kfiber_add_ev_waiter(&mutex->waiter, kgl_get_tls_selector(), data, notice, arg);
	kmutex_unlock(&mutex->lock);
	return kev_ok;
}

void kfiber_add_ev_waiter(kfiber_waiter** head, kselector* selector, KOPAQUE data, result_callback notice, void* arg)
{
	kfiber_event_waiter* waiter = (kfiber_event_waiter*)xmemory_newz(sizeof(kfiber_event_waiter));
	waiter->base.selector = selector;
	waiter->base.next = *head;
	waiter->base.wait_obj = data;
	waiter->result = notice;
	waiter->arg = arg;
	*head = &waiter->base;
}

kev_result kfiber_cond_wait_callback_ar(kfiber_cond* fc, KOPAQUE data, result_callback notice, void* arg)
{
	if (fc->ev>0) {
		fc->ev--;
		kgl_selector_module.next(kgl_get_tls_selector(), data, notice, arg, 0);
		return kev_ok;

	}
	kfiber_add_ev_waiter(&fc->waiter, kgl_get_tls_selector(), data, notice, arg);
	return kev_ok;
}
kev_result kfiber_cond_wait_callback(kfiber_cond * fc, KOPAQUE data, result_callback notice, void* arg)
{
	if (fc->ev>0) {
		kgl_selector_module.next(kgl_get_tls_selector(), data, notice, arg, 0);
		return kev_ok;		
	}
	kfiber_add_ev_waiter(&fc->waiter, kgl_get_tls_selector(), data, notice, arg);
	return kev_ok;
}
kev_result kfiber_cond_wait_callback_ts_ar(kfiber_cond* fc, KOPAQUE data, result_callback notice, void* arg)
{
	kfiber_cond_ts* fcs = (kfiber_cond_ts*)fc;
	kmutex_lock(&fcs->lock);
	if (fc->ev > 0) {
		fc->ev--;
		kmutex_unlock(&fcs->lock);
		kgl_selector_module.next(kgl_get_tls_selector(), data, notice, arg, 0);
		return kev_ok;

	}
	kfiber_add_ev_waiter(&fc->waiter, kgl_get_tls_selector(), data, notice, arg);
	kmutex_unlock(&fcs->lock);
	return kev_ok;
}
kev_result kfiber_cond_wait_callback_ts(kfiber_cond* fc, KOPAQUE data, result_callback notice, void* arg)
{
	kfiber_cond_ts* fcs = (kfiber_cond_ts*)fc;
	kmutex_lock(&fcs->lock);
	if (fc->ev > 0) {
		kmutex_unlock(&fcs->lock);
		kgl_selector_module.next(kgl_get_tls_selector(), data, notice, arg, 0);
		return kev_ok;
	}
	kfiber_add_ev_waiter(&fc->waiter, kgl_get_tls_selector(), data, notice, arg);
	kmutex_unlock(&fcs->lock);
	return kev_ok;
}
int kfiber_cond_notice_ts_ar(kfiber_cond* fc,int got)
{
	kfiber_cond_ts* fcs = (kfiber_cond_ts*)fc;
	kmutex_lock(&fcs->lock);
	kfiber_waiter* waiter = fc->waiter;
	if (waiter) {
		fc->waiter = waiter->next;
		kmutex_unlock(&fcs->lock);
		kfiber_wakeup_waiter(waiter,got);
	} else {
		fc->ev++;
		kmutex_unlock(&fcs->lock);
	}
	return 0;
}
int kfiber_cond_notice_ar(kfiber_cond* fc,int got)
{	
	kfiber_waiter* waiter = fc->waiter;	
	if (waiter) {
		fc->waiter = waiter->next;
		kfiber_wakeup_waiter(waiter,got);
	} else {
		fc->ev++;
	}
	return 0;
}
int kfiber_cond_notice_ts(kfiber_cond* fc,int got)
{
	kfiber_cond_ts* fcs = (kfiber_cond_ts*)fc;
	kmutex_lock(&fcs->lock);
	fc->ev = 1;
	kfiber_waiter* waiter = fc->waiter;
	fc->waiter = NULL;
	kmutex_unlock(&fcs->lock);
	kfiber_wakeup_all_waiter(waiter, got);	
	return 0;
}

int kfiber_cond_notice(kfiber_cond* fc,int got)
{
	fc->ev = 1;
	kfiber_waiter* waiter = fc->waiter;
	fc->waiter = NULL;
	kfiber_wakeup_all_waiter(waiter,got);
	return 0;
}
int kfiber_cond_wait_ts_ar(kfiber_cond* fc, int *got)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	kfiber_cond_ts* fcs = (kfiber_cond_ts*)fc;
	kmutex_lock(&fcs->lock);
	if (fc->ev > 0) {
		fc->ev--;
		kmutex_unlock(&fcs->lock);
		if (got) {
			*got = fiber->retval;
		}
		return 0;
	}
	kfiber_add_waiter(&fc->waiter, fiber, fc);// kgl_get_tls_selector(), & fiber, result_switch_fiber, fiber);
	kmutex_unlock(&fcs->lock);
	__kfiber_wait(fiber, fc);
	if (got) {
		*got = fiber->retval;
	}
	return 0;
}
int kfiber_cond_try_wait_ts_ar(kfiber_cond* fc, int* got) {
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	kfiber_cond_ts* fcs = (kfiber_cond_ts*)fc;
	kmutex_lock(&fcs->lock);
	if (fc->ev > 0) {
		fc->ev--;
		kmutex_unlock(&fcs->lock);
		if (got) {
			*got = fiber->retval;
		}
		return 0;
	}
	kmutex_unlock(&fcs->lock);
	return -1;
}
int kfiber_cond_try_wait_ar(kfiber_cond* fc, int* got) {
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	if (fc->ev > 0) {
		fc->ev--;
		if (got) {
			*got = fiber->retval;
		}
		return 0;
	}
	return -1;
}
int kfiber_cond_wait_ar(kfiber_cond* fc, int *got)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	if (fc->ev > 0) {
		fc->ev--;
		if (got) {
			*got = fiber->retval;
		}
		return 0;
	}
	kfiber_add_waiter(&fc->waiter, fiber, &fiber);// kgl_get_tls_selector(), & fiber, result_switch_fiber, fiber);
	__kfiber_wait(fiber, &fiber);
	if (got) {
		*got = fiber->retval;
	}
	return 0;
}
int kfiber_cond_wait_ts(kfiber_cond* fc, int *got)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	kfiber_cond_ts* fcs = (kfiber_cond_ts*)fc;
	kmutex_lock(&fcs->lock);
	if (fc->ev > 0) {
		if (got) {
			*got = fiber->retval;
		}
		kmutex_unlock(&fcs->lock);
		return 0;
	}
	kfiber_add_waiter(&fc->waiter, fiber, &fiber);// kgl_get_tls_selector(), & fiber, result_switch_fiber, fiber);
	kmutex_unlock(&fcs->lock);
	__kfiber_wait(fiber, &fiber);
	if (got) {
		*got = fiber->retval;
	}
	return 0;
}

int kfiber_cond_try_wait_ts(kfiber_cond* fc, int* got) {
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	kfiber_cond_ts* fcs = (kfiber_cond_ts*)fc;
	kmutex_lock(&fcs->lock);
	if (fc->ev > 0) {
		if (got) {
			*got = fiber->retval;
		}
		kmutex_unlock(&fcs->lock);
		return 0;
	}
	kmutex_unlock(&fcs->lock);
	return -1;
}
int kfiber_cond_notice_sync(kfiber_cond* fc, int got)
{
	kfiber_cond_sync* sync = (kfiber_cond_sync*)fc;
	sync->got = got;
	kcond_notice(sync->sync_cond);
	return 0;
}
int kfiber_cond_wait_sync(kfiber_cond* fc, int *got)
{
	assert(kfiber_self() == NULL);
	kfiber_cond_sync* sync = (kfiber_cond_sync*)fc;
	kcond_wait(sync->sync_cond);
	if (got) {
		*got = sync->got;
	}
	return 0;
}
int kfiber_cond_try_wait_sync(kfiber_cond* fc, int* got) {
	assert(kfiber_self() == NULL);
	kfiber_cond_sync* sync = (kfiber_cond_sync*)fc;
	if (!kcond_try_wait(sync->sync_cond, 0)) {
		return -1;
	}
	if (got) {
		*got = sync->got;
	}
	return 0;
}
int kfiber_cond_wait(kfiber_cond* fc, int *got)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	if (fc->ev > 0) {
		if (got) {
			*got = fiber->retval;
		}
		return 0;
	}
	kfiber_add_waiter(&fc->waiter, fiber, &fiber);// kgl_get_tls_selector(), & fiber, result_switch_fiber, fiber);
	__kfiber_wait(fiber, &fiber);
	if (got) {
		*got = fiber->retval;
	}
	return 0;
}
int kfiber_cond_try_wait(kfiber_cond* fc, int* got) {
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	if (fc->ev > 0) {
		if (got) {
			*got = fiber->retval;
		}
		return 0;
	}
	return -1;
}
void kfiber_cond_destroy(kfiber_cond* fc)
{
	assert(fc->waiter == NULL);
	//kmutex_destroy(&fc->lock);
	free(fc);
}
void kfiber_cond_destroy_ts(kfiber_cond* fc)
{
	assert(fc->waiter == NULL);
	kmutex_destroy(&((kfiber_cond_ts *)fc)->lock);
	xfree(fc);
}
void kfiber_cond_destroy_sync(kfiber_cond* fc)
{
	assert(fc->waiter == NULL);
	kcond_destroy(((kfiber_cond_sync*)fc)->sync_cond);
	xfree(fc);
}
static kfiber_cond_function kfiber_cond_single_thread_auto_reset = {
	kfiber_cond_notice_ar,
	kfiber_cond_wait_ar,
	kfiber_cond_try_wait_ar,
	kfiber_cond_wait_callback_ar,
	kfiber_cond_destroy
};
static kfiber_cond_function kfiber_cond_single_thread = {
	kfiber_cond_notice,
	kfiber_cond_wait,
	kfiber_cond_try_wait,
	kfiber_cond_wait_callback,
	kfiber_cond_destroy
};
static kfiber_cond_function kfiber_cond_thread_auto_reset = {
	kfiber_cond_notice_ts_ar,
	kfiber_cond_wait_ts_ar,
	kfiber_cond_try_wait_ts_ar,
	kfiber_cond_wait_callback_ts_ar,
	kfiber_cond_destroy_ts
};
static kfiber_cond_function kfiber_cond_thread_safe = {
	kfiber_cond_notice_ts,
	kfiber_cond_wait_ts,
	kfiber_cond_try_wait_ts,
	kfiber_cond_wait_callback_ts,
	kfiber_cond_destroy_ts
};
static kfiber_cond_function kfiber_cond_thread_sync = {
	kfiber_cond_notice_sync,
	kfiber_cond_wait_sync,
	kfiber_cond_try_wait_sync,
	NULL,
	kfiber_cond_destroy_sync
};
kfiber_cond* kfiber_cond_init(bool auto_reset)
{
	kfiber_cond* fc = (kfiber_cond*)xmemory_newz(sizeof(kfiber_cond));
	if (auto_reset) {
		fc->f = &kfiber_cond_single_thread_auto_reset;
	} else {
		fc->f = &kfiber_cond_single_thread;
	}
	return fc;
}
//thread safe
kfiber_cond* kfiber_cond_init_ts(bool auto_reset)
{
	kfiber_cond_ts *fc = (kfiber_cond_ts *)xmemory_newz(sizeof(kfiber_cond_ts));
	kmutex_init(&fc->lock, NULL);
	if (auto_reset) {
		fc->base.f = &kfiber_cond_thread_auto_reset;
	} else {
		fc->base.f = &kfiber_cond_thread_safe;
	}
	return (kfiber_cond *)fc;
}
//support worker thread wait fiber
kfiber_cond* kfiber_cond_init_sync(bool auto_reset)
{
	kfiber_cond_sync* fc = (kfiber_cond_sync*)xmemory_newz(sizeof(kfiber_cond_sync));
	fc->sync_cond = kcond_init(auto_reset);
	fc->base.f = &kfiber_cond_thread_sync;
	return (kfiber_cond*)fc;
}


//chan
void kfiber_chan_wakeup(kfiber_chan* ch, kfiber_waiter* waiter, int got) {
	_kfiber_wakeup_waiter(waiter, ch, got);
}
kfiber_chan* kfiber_chan_create() {
	kfiber_chan* ch = (kfiber_chan*)xmemory_newz(sizeof(kfiber_chan));
	ch->ref = 1;
	return ch;
}
int kfiber_chan_send(kfiber_chan* ch, KOPAQUE data) {
	kfiber* fiber = kfiber_self();
	assert(fiber);
	CHECK_FIBER(fiber);
	if (ch->closed) {
		return -1;
	}
	switch (ch->wait_flag) {
	case KFIBER_CHAN_NO_WAITER:
		ch->wait_flag = KFIBER_CHAN_SEND_WAITER;
		assert(ch->waiter == NULL);
		kfiber_add_waiter(&ch->waiter, fiber, data);
		return __kfiber_wait(fiber, ch);
	case KFIBER_CHAN_SEND_WAITER:
		assert(ch->waiter != NULL);
		assert(ch->waiter->selector == fiber->base.selector);
		kfiber_add_waiter(&ch->waiter, fiber, data);
		return __kfiber_wait(fiber, ch);
	case KFIBER_CHAN_RECV_WAITER: {
		assert(ch->waiter != NULL);
		assert(ch->waiter->selector == fiber->base.selector);
		kfiber_waiter* waiter = ch->waiter;
		ch->waiter = waiter->next;
		if (ch->waiter == NULL) {
			ch->wait_flag = KFIBER_CHAN_NO_WAITER;
		}
		waiter->wait_obj = data;
		kfiber_chan_wakeup(ch, waiter, 0);
		return 0;
	}
	default:
		assert(false);
		return -1;
	}
}
int kfiber_chan_recv(kfiber_chan* ch, KOPAQUE* data, kfiber_waiter** sender) {
	kfiber* fiber = kfiber_self();
	int retval;
	CHECK_FIBER(fiber);
	switch (ch->wait_flag) {
	case KFIBER_CHAN_NO_WAITER:
		assert(ch->waiter == NULL);
		if (ch->closed) {
			return -1;
		}
		ch->wait_flag = KFIBER_CHAN_RECV_WAITER;
		kfiber_add_waiter(&ch->waiter, fiber, NULL);
		retval = __kfiber_wait(fiber, ch);
		*data = fiber->base.wait_obj;
		if (sender) {
			*sender = NULL;
		}
		return retval;
	case KFIBER_CHAN_RECV_WAITER:
		assert(ch->waiter != NULL);
		assert(ch->waiter->selector == fiber->base.selector);
		if (ch->closed) {
			return -1;
		}
		kfiber_add_waiter(&ch->waiter, fiber, NULL);
		retval = __kfiber_wait(fiber, ch);
		*data = fiber->base.wait_obj;
		if (sender) {
			*sender = NULL;
		}
		return retval;
	case KFIBER_CHAN_SEND_WAITER: {
		assert(ch->waiter != NULL);
		assert(ch->waiter->selector == fiber->base.selector);
		kfiber_waiter* waiter = ch->waiter;
		ch->waiter = waiter->next;
		if (ch->waiter == NULL) {
			ch->wait_flag = KFIBER_CHAN_NO_WAITER;
		}
		*data = waiter->wait_obj;
		if (sender) {
			*sender = waiter;
		} else {
			kfiber_chan_wakeup(ch, waiter, 0);
		}
		return 0;
	}
	default:
		assert(false);
		return -1;
	}
	return 0;
}
int kfiber_chan_close(kfiber_chan* ch) {
	if (ch->closed) {
		//already closed;
		assert(ch->waiter == NULL);
		return 0;
	}
	ch->closed = 1;
	kfiber_waiter* waiter = ch->waiter;
	ch->waiter = NULL;
	ch->wait_flag = KFIBER_CHAN_NO_WAITER;
	while (waiter) {
		assert(waiter->selector == kfiber_self()->base.selector);
		kfiber_waiter* next = waiter->next;
		waiter->wait_obj = NULL;
		kfiber_chan_wakeup(ch, waiter, -1);
		waiter = next;
	}
	return 0;
}
kfiber_chan* kfiber_chan_add_ref(kfiber_chan* ch) {
	katom_inc((void*)&ch->ref);
	return ch;
}
int kfiber_chan_get_ref(kfiber_chan* ch) {
	return (int)katom_get((void*)&ch->ref);
}
int kfiber_chan_release(kfiber_chan* ch) {
	if (katom_dec((void*)&ch->ref) == 0) {
		assert(ch->waiter == NULL);
		xfree(ch);
	}
	return 0;
}

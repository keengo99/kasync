#include "kfiber_sync.h"
#include "ksync.h"
#include "kfiber_internal.h"
#include "kfiber.h"

typedef struct _kfiber_cond_ts kfiber_cond_ts;
typedef struct _kfiber_cond_sync kfiber_cond_sync;

struct _kfiber_cond_ts {
	kfiber_cond base;
	kmutex lock;
};

struct _kfiber_mutex {
	kfiber_waiter* waiter;
	kmutex lock;
	int count;// 总数
	int worker;//获得锁数量
	int limit;//最多几个同时获得锁
};

struct _kfiber_rwlock {
	kfiber_waiter* reader;
	kfiber_waiter* writer;
	kmutex lock;
	volatile int32_t cnt;
};

struct _kfiber_cond_sync
{
	kfiber_cond base;
	kcond* sync_cond;
	int got;
};
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
	kfiber_add_waiter(&mutex->waiter, kgl_get_tls_selector(), data, notice, arg);
	kmutex_unlock(&mutex->lock);
	return kev_ok;
}
kfiber_mutex* kfiber_mutex_init()
{
	return kfiber_mutex_init2(1);
}
kfiber_mutex* kfiber_mutex_init2(int num)
{
	kfiber_mutex* fc = (kfiber_mutex*)xmemory_newz(sizeof(kfiber_mutex));
	kmutex_init(&fc->lock, NULL);
	fc->limit = num;
	return fc;
}
int kfiber_mutex_get_worker(kfiber_mutex* mutex)
{
	int worker;
	kmutex_lock(&mutex->lock);
	worker = mutex->worker;
	kmutex_unlock(&mutex->lock);
	return worker;
}
int kfiber_mutex_get_count(kfiber_mutex* mutex)
{
	int count;
	kmutex_lock(&mutex->lock);
	count = mutex->count;
	kmutex_unlock(&mutex->lock);
	return count;
}
int kfiber_mutex_get_limit(kfiber_mutex* mutex)
{
	int limit;
	kmutex_lock(&mutex->lock);
	limit = mutex->limit;
	kmutex_unlock(&mutex->lock);
	return limit;
}
void kfiber_mutex_set_limit(kfiber_mutex* mutex, int limit)
{
	if (limit < 1) {
		limit = 1;
	}
	kmutex_lock(&mutex->lock);
	mutex->limit = limit;
	kmutex_unlock(&mutex->lock);
}
int __kfiber_mutex_lock(kfiber* fiber, kfiber_mutex* mutex, int max)
{
	kmutex_lock(&mutex->lock);
	if (max > 0 && mutex->count >= max) {
		kmutex_unlock(&mutex->lock);
		return -1;
	}
	mutex->count++;
	if (mutex->worker < mutex->limit) {
		mutex->worker++;
		kmutex_unlock(&mutex->lock);
		return 0;
	}
	kfiber_add_waiter(&mutex->waiter, kgl_get_tls_selector(), mutex, result_switch_fiber, fiber);
	kmutex_unlock(&mutex->lock);
	__kfiber_wait(fiber, mutex);
	return 0;
}
int kfiber_mutex_try_lock(kfiber_mutex* mutex, int max)
{
	kfiber* fiber = kfiber_self();
	assert(fiber);
	CHECK_FIBER(fiber);
	return __kfiber_mutex_lock(fiber, mutex, max);
}
int kfiber_mutex_lock(kfiber_mutex* mutex)
{
	kfiber* fiber = kfiber_self();
	assert(fiber);
	CHECK_FIBER(fiber);
	return __kfiber_mutex_lock(fiber, mutex, 0);
}
int kfiber_mutex_unlock(kfiber_mutex* mutex)
{
	kmutex_lock(&mutex->lock);
	assert(mutex->count > 0);
	mutex->count--;	
	kfiber_waiter* waiter = mutex->waiter;
	if (waiter == NULL) {
		assert(mutex->worker > 0);
		mutex->worker--;
		kmutex_unlock(&mutex->lock);
		return 0;
	}
	mutex->waiter = waiter->next;
	kmutex_unlock(&mutex->lock);
	kfiber_wakeup_waiter(waiter,0);
	xfree(waiter);
	return 0;
}
void kfiber_mutex_destroy(kfiber_mutex* mutex)
{
	assert(mutex->waiter == NULL);
	kmutex_destroy(&mutex->lock);
	free(mutex);
}

void kfiber_add_waiter(kfiber_waiter** head, kselector* selector, KOPAQUE data, result_callback notice, void* arg)
{
	kfiber_waiter* waiter = (kfiber_waiter*)xmemory_newz(sizeof(kfiber_waiter));
	waiter->data = data;
	waiter->selector = selector;
	waiter->next = *head;
	waiter->notice = notice;
	waiter->arg = arg;
	*head = waiter;
}
kev_result kfiber_cond_wait_callback_ar(kfiber_cond* fc, KOPAQUE data, result_callback notice, void* arg)
{
	if (fc->ev>0) {
		fc->ev--;
		kgl_selector_module.next(kgl_get_tls_selector(), data, notice, arg, 0);
		return kev_ok;

	}
	kfiber_add_waiter(&fc->waiter, kgl_get_tls_selector(), data, notice, arg);
	return kev_ok;
}
kev_result kfiber_cond_wait_callback(kfiber_cond * fc, KOPAQUE data, result_callback notice, void* arg)
{
	if (fc->ev>0) {
		kgl_selector_module.next(kgl_get_tls_selector(), data, notice, arg, 0);
		return kev_ok;		
	}
	kfiber_add_waiter(&fc->waiter, kgl_get_tls_selector(), data, notice, arg);
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
	kfiber_add_waiter(&fc->waiter, kgl_get_tls_selector(), data, notice, arg);
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
	kfiber_add_waiter(&fc->waiter, kgl_get_tls_selector(), data, notice, arg);
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
		xfree(waiter);
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
		xfree(waiter);
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
	while (waiter) {
		kfiber_waiter* next = waiter->next;
		kfiber_wakeup_waiter(waiter,got);
		xfree(waiter);
		waiter = next;
	}
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
	kfiber_add_waiter(&fc->waiter, kgl_get_tls_selector(), &fiber, result_switch_fiber, fiber);
	kmutex_unlock(&fcs->lock);
	__kfiber_wait(fiber, &fiber);
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
	kfiber_add_waiter(&fc->waiter, kgl_get_tls_selector(), &fiber, result_switch_fiber, fiber);
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
	kfiber_add_waiter(&fc->waiter, kgl_get_tls_selector(), &fiber, result_switch_fiber, fiber);
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
	kfiber_add_waiter(&fc->waiter, kgl_get_tls_selector(), &fiber, result_switch_fiber, fiber);
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
kfiber_rwlock* kfiber_rwlock_init()
{
	kfiber_rwlock* mutex = (kfiber_rwlock *)xmemory_newz(sizeof(kfiber_rwlock));
	kmutex_init(&mutex->lock, NULL);
	return mutex;
}
int kfiber_rwlock_rlock(kfiber_rwlock* mutex)
{
	kfiber* fiber = kfiber_self();
	assert(!kfiber_is_main());
	CHECK_FIBER(fiber);
	kmutex_lock(&mutex->lock);
	if (mutex->cnt < 0 || mutex->writer) {
		/* write lock is held or has write waiter*/
		kfiber_add_waiter(&mutex->reader, fiber->selector, &fiber, result_switch_fiber, fiber);
		kmutex_unlock(&mutex->lock);
		return __kfiber_wait(fiber, &fiber);
	}
	mutex->cnt++;
	kmutex_unlock(&mutex->lock);
	return 0;
}
int kfiber_rwlock_wlock(kfiber_rwlock* mutex)
{
	kfiber* fiber = kfiber_self();
	assert(!kfiber_is_main());
	CHECK_FIBER(fiber);
	kmutex_lock(&mutex->lock);
	if (mutex->cnt != 0) {
		kfiber_add_waiter(&mutex->writer, fiber->selector, &fiber, result_switch_fiber, fiber);
		kmutex_unlock(&mutex->lock);
		return __kfiber_wait(fiber, &fiber);
	}
	mutex->cnt = -1;
	kmutex_unlock(&mutex->lock);
	return 0;
}
INLINE int __kfiber_rwlock_try_wakeup_writer(kfiber_rwlock* mutex)
{
	if (mutex->writer) {
		mutex->cnt = -1;
		kfiber_waiter* writer = mutex->writer;
		mutex->writer = writer->next;
		kmutex_unlock(&mutex->lock);
		kfiber_wakeup_waiter(writer,0);
		xfree(writer);
		return 0;
	}
	kmutex_unlock(&mutex->lock);
	return 0;
}
int kfiber_rwlock_runlock(kfiber_rwlock* mutex)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	kmutex_lock(&mutex->lock);
	assert(mutex->cnt > 0);
	mutex->cnt--;
	if (mutex->cnt == 0) {
		return __kfiber_rwlock_try_wakeup_writer(mutex);
	}
	kmutex_unlock(&mutex->lock);
	return 0;
}
int kfiber_rwlock_wunlock(kfiber_rwlock* mutex)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	kmutex_lock(&mutex->lock);
	assert(mutex->cnt == -1);
	mutex->cnt = 0;
	if (mutex->reader) {
		kfiber_waiter* waiter = mutex->reader;
		mutex->reader = NULL;
		while (waiter) {
			mutex->cnt++;
			kfiber_waiter* next = waiter->next;
			kfiber_wakeup_waiter(waiter,0);
			xfree(waiter);
			waiter = next;
		}
		kmutex_unlock(&mutex->lock);
		return 0;
	}
	return __kfiber_rwlock_try_wakeup_writer(mutex);
}
void kfiber_rwlock_destroy(kfiber_rwlock* mutex)
{
	assert(mutex->cnt == 0);
	assert(mutex->reader == NULL);
	assert(mutex->writer == NULL);
	kmutex_destroy(&mutex->lock);
	xfree(mutex);
}

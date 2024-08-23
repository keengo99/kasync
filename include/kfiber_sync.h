#ifndef KFIBER_SYNC_H
#define KFIBER_SYNC_H
#include "kfeature.h"
#include "kfiber_internal.h"
#include "ksync.h"
#include "kfiber.h"
KBEGIN_DECLS
//thread safe mutex

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

INLINE int __kfiber_mutex_lock(kfiber* fiber, kfiber_mutex* mutex, int max) {
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
	kfiber_add_waiter(&mutex->waiter, fiber, mutex);// kgl_get_tls_selector(), mutex, result_switch_fiber, fiber);
	kmutex_unlock(&mutex->lock);
	__kfiber_wait(fiber, mutex);
	return 0;
}
INLINE kfiber_mutex* kfiber_mutex_init2(int num) {
	kfiber_mutex* fc = (kfiber_mutex*)xmemory_newz(sizeof(kfiber_mutex));
	kmutex_init(&fc->lock, NULL);
	fc->limit = num;
	return fc;
}
INLINE kfiber_mutex* kfiber_mutex_init() {
	return kfiber_mutex_init2(1);
}
INLINE int kfiber_mutex_get_limit(kfiber_mutex* mutex) {
	int limit;
	kmutex_lock(&mutex->lock);
	limit = mutex->limit;
	kmutex_unlock(&mutex->lock);
	return limit;
}
INLINE void kfiber_mutex_set_limit(kfiber_mutex* mutex, int limit) {
	if (limit < 1) {
		limit = 1;
	}
	kmutex_lock(&mutex->lock);
	mutex->limit = limit;
	kmutex_unlock(&mutex->lock);
}
INLINE int kfiber_mutex_get_worker(kfiber_mutex* mutex) {
	int worker;
	kmutex_lock(&mutex->lock);
	worker = mutex->worker;
	kmutex_unlock(&mutex->lock);
	return worker;
}
INLINE int kfiber_mutex_get_count(kfiber_mutex* mutex) {
	int count;
	kmutex_lock(&mutex->lock);
	count = mutex->count;
	kmutex_unlock(&mutex->lock);
	return count;
}
INLINE int kfiber_mutex_lock(kfiber_mutex* mutex) {
	kfiber* fiber = kfiber_self();
	assert(fiber);
	CHECK_FIBER(fiber);
	return __kfiber_mutex_lock(fiber, mutex, 0);
}
INLINE int kfiber_mutex_try_lock(kfiber_mutex* mutex, int max) {
	kfiber* fiber = kfiber_self();
	assert(fiber);
	CHECK_FIBER(fiber);
	return __kfiber_mutex_lock(fiber, mutex, max);
}

INLINE int kfiber_mutex_unlock(kfiber_mutex* mutex) {
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
	kfiber_wakeup_waiter(waiter, 0);
	return 0;
}
INLINE void kfiber_mutex_destroy(kfiber_mutex* mutex) {
	assert(mutex->waiter == NULL);
	kmutex_destroy(&mutex->lock);
	free(mutex);
}

kev_result kfiber_mutex_lock2(kfiber_mutex* mutex, KOPAQUE data, result_callback notice, void* arg);

INLINE kfiber_rwlock* kfiber_rwlock_init() {
	kfiber_rwlock* mutex = (kfiber_rwlock*)xmemory_newz(sizeof(kfiber_rwlock));
	kmutex_init(&mutex->lock, NULL);
	return mutex;
}

INLINE int kfiber_rwlock_rlock(kfiber_rwlock* mutex) {
	kfiber* fiber = kfiber_self();
	assert(!kfiber_is_main());
	CHECK_FIBER(fiber);
	kmutex_lock(&mutex->lock);
	if (mutex->cnt < 0 || mutex->writer) {
		/* write lock is held or has write waiter*/
		kfiber_add_waiter(&mutex->reader, fiber, &fiber);// fiber->base.selector, & fiber, result_switch_fiber, fiber);
		kmutex_unlock(&mutex->lock);
		return __kfiber_wait(fiber, &fiber);
	}
	mutex->cnt++;
	kmutex_unlock(&mutex->lock);
	return 0;
}
INLINE int kfiber_rwlock_wlock(kfiber_rwlock* mutex) {
	kfiber* fiber = kfiber_self();
	assert(!kfiber_is_main());
	CHECK_FIBER(fiber);
	kmutex_lock(&mutex->lock);
	if (mutex->cnt != 0) {
		kfiber_add_waiter(&mutex->writer, fiber, &fiber);// fiber->base.selector, & fiber, result_switch_fiber, fiber);
		kmutex_unlock(&mutex->lock);
		return __kfiber_wait(fiber, &fiber);
	}
	mutex->cnt = -1;
	kmutex_unlock(&mutex->lock);
	return 0;
}
INLINE int __kfiber_rwlock_try_wakeup_writer(kfiber_rwlock* mutex) {
	if (mutex->writer) {
		mutex->cnt = -1;
		kfiber_waiter* writer = mutex->writer;
		mutex->writer = writer->next;
		kmutex_unlock(&mutex->lock);
		kfiber_wakeup_waiter(writer, 0);
		return 0;
	}
	kmutex_unlock(&mutex->lock);
	return 0;
}
INLINE int kfiber_rwlock_runlock(kfiber_rwlock* mutex) {
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
INLINE int kfiber_rwlock_wunlock(kfiber_rwlock* mutex) {
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
			kfiber_wakeup_waiter(waiter, 0);
			waiter = next;
		}
		kmutex_unlock(&mutex->lock);
		return 0;
	}
	return __kfiber_rwlock_try_wakeup_writer(mutex);
}
INLINE void kfiber_rwlock_destroy(kfiber_rwlock* mutex) {
	assert(mutex->cnt == 0);
	assert(mutex->reader == NULL);
	assert(mutex->writer == NULL);
	kmutex_destroy(&mutex->lock);
	xfree(mutex);
}

//kfiber cond wait
kfiber_cond* kfiber_cond_init(bool auto_reset);
kfiber_cond* kfiber_cond_init_ts(bool auto_reset);
kfiber_cond* kfiber_cond_init_sync(bool auto_reset);

//kfiber chan
/* NOT support thread safe */
kfiber_chan* kfiber_chan_create();
int kfiber_chan_send(kfiber_chan* ch, KOPAQUE data);
int kfiber_chan_recv(kfiber_chan* ch, KOPAQUE* data, kfiber_waiter **sender);
int kfiber_chan_close(kfiber_chan* ch);
kfiber_chan* kfiber_chan_add_ref(kfiber_chan* ch);
void kfiber_chan_wakeup(kfiber_chan* ch, kfiber_waiter* waiter, int got);
int kfiber_chan_get_ref(kfiber_chan* ch);
int kfiber_chan_release(kfiber_chan* ch);
KEND_DECLS
#endif

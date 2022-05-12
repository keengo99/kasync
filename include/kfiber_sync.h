#ifndef KFIBER_SYNC_H
#define KFIBER_SYNC_H
#include "kfeature.h"
#include "kfiber_internal.h"
KBEGIN_DECLS
//thread safe mutex
kfiber_mutex* kfiber_mutex_init();
kfiber_mutex* kfiber_mutex_init2(int limit);
int kfiber_mutex_get_limit(kfiber_mutex* mutex);
void kfiber_mutex_set_limit(kfiber_mutex* mutex, int limit);
int kfiber_mutex_get_worker(kfiber_mutex* mutex);
int kfiber_mutex_get_count(kfiber_mutex* mutex);
int kfiber_mutex_lock(kfiber_mutex* mutex);
int kfiber_mutex_try_lock(kfiber_mutex* mutex, int max);
int kfiber_mutex_unlock(kfiber_mutex* mutex);
void kfiber_mutex_destroy(kfiber_mutex* mutex);
kev_result kfiber_mutex_lock2(kfiber_mutex* mutex, KOPAQUE data, result_callback notice, void* arg);

kfiber_rwlock* kfiber_rwlock_init();
int kfiber_rwlock_rlock(kfiber_rwlock* mutex);
int kfiber_rwlock_wlock(kfiber_rwlock* mutex);
int kfiber_rwlock_runlock(kfiber_rwlock* mutex);
int kfiber_rwlock_wunlock(kfiber_rwlock* mutex);
void kfiber_rwlock_destroy(kfiber_rwlock* mutex);

//kfiber cond wait
kfiber_cond* kfiber_cond_init(bool auto_reset);
kfiber_cond* kfiber_cond_init_ts(bool auto_reset);
kfiber_cond* kfiber_cond_init_sync(bool auto_reset);
KEND_DECLS
#endif

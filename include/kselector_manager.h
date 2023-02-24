#ifndef KSELECTOR_MANAGER_H_99
#define KSELECTOR_MANAGER_H_99
#include "kfeature.h"
#include "kselector.h"
#include "kserver.h"
KBEGIN_DECLS
int get_selector_count();
void selector_manager_init(int size,bool register_thread_timer);
bool selector_manager_grow(int new_size);
void selector_manager_on_ready(result_callback cb, void *arg);
int selector_manager_thread_init(result_callback cb, void *arg);
void selector_manager_add_timer(result_callback timer,void *arg, int msec, KOPAQUE data);
void kselector_add_timer_ts(kselector *selector,result_callback timer, void *arg, int msec, KOPAQUE data);
bool is_selector_manager_init();

void selector_manager_start(void(*time_hook)(), bool thread);

void selector_manager_close();
void selector_manager_set_timeout(int connect_tmo_sec,int rw_tmo_sec);
void selector_manager_adjust_time(int64_t diff_time);
kselector *get_perfect_selector();
kselector *get_selector_by_index(int index);
void kselector_step_init(int index);
int kselector_step(int index);
void kselector_step_exit(int index);
int kasync_main(kfiber_start_func main, void* arg, int argc);
void kasync_init();
const char *selector_manager_event_name();
KEND_DECLS
#endif


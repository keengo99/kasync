#ifndef KEPOLL_SELECTOR_H_99
#define KEPOLL_SELECTOR_H_99
#include "kselectable.h"
#include "ksync.h"
#ifdef LINUX_EPOLL
void kepoll_module_init();
#endif
typedef struct kepoll_notice_selectable_s kepoll_notice_selectable;
struct kepoll_notice_selectable_s {
        kselectable st;
        kmutex lock;
	kselector_notice *head;
};
void kepoll_notice_init(kselector *selector,kepoll_notice_selectable *notice_st,result_callback result,void *arg);
void kepoll_notice(kepoll_notice_selectable *notice_st, KOPAQUE data, result_callback result, void *arg, int got);
void kepoll_notice_event(kepoll_notice_selectable *notice_st);
#endif

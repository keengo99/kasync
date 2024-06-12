#ifndef KEPOLL_SELECTOR_H_99
#define KEPOLL_SELECTOR_H_99
#include "kselectable.h"
#include "ksync.h"
#ifndef _WIN32
struct kepoll_notice_selectable_s {
        kselectable st;
        kmutex lock;
	kselector_notice *head;
};
typedef struct kepoll_notice_selectable_s kepoll_notice_selectable;
#endif
#ifdef LINUX
#ifdef LINUX_EPOLL
void kepoll_module_init();
#endif
void kepoll_notice_init(kselector *selector,kepoll_notice_selectable *notice_st,result_callback result,void *arg);
INLINE void kepoll_notice_event(kepoll_notice_selectable* ast) {
	uint64_t value;
	if (read(ast->st.fd, &value, sizeof(value)) != sizeof(value)) {
		perror("read");
		return;
	}
	while (value > 0) {
		kmutex_lock(&ast->lock);
		kselector_notice* notice = ast->head;
		kassert(notice != NULL);
		ast->head = notice->next;
		kmutex_unlock(&ast->lock);
		value--;
		notice->result(notice->data, notice->arg, notice->got);
		xfree(notice);
	}
}
INLINE void kepoll_notice(kepoll_notice_selectable* notice_st, KOPAQUE data, result_callback result, void* arg, int got) {
	kselector_notice* notice = (kselector_notice*)xmalloc(sizeof(kselector_notice));
	memset(notice, 0, sizeof(kselector_notice));
	notice->data = data;
	notice->arg = arg;
	notice->result = result;
	notice->got = got;
	kmutex_lock(&notice_st->lock);
	notice->next = notice_st->head;
	notice_st->head = notice;
	kmutex_unlock(&notice_st->lock);
	uint64_t value = 1;
	write(notice_st->st.fd, &value, sizeof(value));
}
#endif
#endif

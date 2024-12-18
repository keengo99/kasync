#include "kfeature.h"
#ifdef LINUX

#include <sys/epoll.h>
#include <errno.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include "kselectable.h"
#include "kserver.h"
#include "ksocket.h"
#include "klist.h"
#include "ksync.h"
#include "klog.h"
#include "klist.h"
#include "kasync_file.h"
#include "kmalloc.h"
#include "kepoll_selector.h"
#include "kfiber.h"

#define MAXEVENT	512

#ifdef LINUX_EPOLL
typedef struct {
	kselectable st;
	aio_context_t aio_ctx;
} kepoll_aio_selectable;

typedef struct {
	int kdpfd;
	kepoll_notice_selectable notice_st;
	kepoll_aio_selectable aio_st;
} kepoll_selector;

static INLINE int io_setup(u_int nr_reqs, aio_context_t *ctx)
{
    return syscall(SYS_io_setup, nr_reqs, ctx);
}
static INLINE int io_destroy(aio_context_t ctx)
{
    return syscall(SYS_io_destroy, ctx);
}
static INLINE int io_getevents(aio_context_t ctx, long min_nr, long nr, struct io_event *events, struct timespec *tmo)
{
    return syscall(SYS_io_getevents, ctx, min_nr, nr, events, tmo);
}
static INLINE int io_submit(aio_context_t ctx, long n, struct iocb **paiocb)
{
    return syscall(SYS_io_submit, ctx, n, paiocb);
}

static kev_result result_notice_event(KOPAQUE data, void *arg,int got)
{
	kepoll_notice_selectable *ast = (kepoll_notice_selectable *)arg;
	assert(got==0);
	kepoll_notice_event(ast);
	return kev_ok;
}
static INLINE void aio_result(kasync_file *file,struct iocb *iocb, long res, long res2)
{
	file->st.e[OP_READ].result(file->st.data,file->st.e[OP_READ].arg,kasync_file_adjust_result(file,(int)res));
}
static kev_result result_aio_event(KOPAQUE data, void *arg,int got)
{
	kepoll_aio_selectable *aio_st = (kepoll_aio_selectable *)arg;
	kassert(got==0);
	uint64_t finished_aio;
	int i,j,r;
	struct timespec tms;
	if (read(aio_st->st.fd, &finished_aio, sizeof(finished_aio)) != sizeof(finished_aio)) {
	   perror("read");
	   return kev_err;
	}
	struct io_event events[MAXEVENT];

	while (finished_aio > 0)  {
		   tms.tv_sec = 0;
		   tms.tv_nsec = 0;
		   int get_events = finished_aio;
		   if (get_events>MAXEVENT) {
				   get_events = MAXEVENT;
		   }
		   r = io_getevents(aio_st->aio_ctx, 1, get_events, events, &tms);
		   if (r > 0) {
				   for (j = 0; j < r; ++j) {
						   kasync_file *ctx = (kasync_file *)events[j].data;
						   aio_result(ctx,(struct iocb *)events[j].obj, events[j].res, events[j].res2);
				   }
				   i += r;
				   finished_aio -= r;
		   }
	}
	return kev_ok;

}
static INLINE bool epoll_add_event(int kdpfd,kselectable *st,uint16_t ev)
{
	struct epoll_event event;
	int op = EPOLL_CTL_ADD;
	uint32_t events = 0;
	uint16_t prev_ev = st->base.st_flags;
	if (KBIT_TEST(ev,STF_REV)) {
		events |= EPOLLIN|EPOLLRDHUP|EPOLLET;
		if (KBIT_TEST(prev_ev,STF_WEV)) {
			op = EPOLL_CTL_MOD;
			events|=EPOLLOUT;
		}
		KBIT_SET(st->base.st_flags,STF_REV|STF_ET|STF_WREADY);
	}
	if (KBIT_TEST(ev,STF_WEV)) {
		events |= EPOLLOUT|EPOLLRDHUP|EPOLLET;
		if (KBIT_TEST(prev_ev,STF_REV)) {
			op = EPOLL_CTL_MOD;
			events|=EPOLLIN;
		}
		KBIT_SET(st->base.st_flags,STF_WEV|STF_ET);
	}
	SOCKET sockfd = st->fd;
	event.events = events;
#ifndef NDEBUG
//	klog(KLOG_DEBUG,"%s event [%d] epoll event=[%lld] sockfd=[%d],st=[%p]\n",op==EPOLL_CTL_ADD?"add":"modify",ev,int64_t(events),sockfd,st);
#endif
	event.data.ptr = st;
	int ret = epoll_ctl(kdpfd, op, sockfd, &event);
	if (ret !=0) {
		klog(KLOG_ERR, "epoll ctl error fd=%d,errno=%d %s\n", sockfd,errno,strerror(errno));
		return false;
	}
	return true;
}

static void epoll_selector_init(kselector *selector)
{
	kepoll_selector *ctx = (kepoll_selector *)xmalloc(sizeof(kepoll_selector));
	memset(ctx,0,sizeof(kepoll_selector));
#ifdef EPOLL_CLOEXEC
	ctx->kdpfd = epoll_create1(EPOLL_CLOEXEC);
#else
	ctx->kdpfd = epoll_create(MAXEVENT);
#endif
	kepoll_notice_init(selector,&ctx->notice_st,result_notice_event,&ctx->notice_st);
	KBIT_SET(ctx->notice_st.st.base.st_flags,STF_READ|STF_REV);
	struct epoll_event epevent;
	epevent.events = EPOLLIN;
	epevent.data.ptr = &ctx->notice_st.st;
	if (epoll_ctl(ctx->kdpfd, EPOLL_CTL_ADD, ctx->notice_st.st.fd, &epevent)) {
		perror("epoll_ctl");
	}

	//init aio_st
	ctx->aio_st.st.base.selector = selector;
	KBIT_SET(ctx->aio_st.st.base.st_flags,STF_READ|STF_REV);
	ctx->aio_st.st.e[OP_READ].arg = &ctx->aio_st;
	ctx->aio_st.st.e[OP_READ].result = result_aio_event;
	ctx->aio_st.st.fd = eventfd(0, EFD_CLOEXEC);

	epevent.data.ptr = &ctx->aio_st.st;
	if (epoll_ctl(ctx->kdpfd, EPOLL_CTL_ADD, ctx->aio_st.st.fd, &epevent)) {
		perror("epoll_ctl");
	}
	memset(&ctx->aio_st.aio_ctx,0,sizeof(ctx->aio_st.aio_ctx));
	if (io_setup(128, &ctx->aio_st.aio_ctx)) {
			perror("io_setup");
	}

	selector->ctx = (void *)ctx;
}
static void epoll_selector_destroy(kselector *selector)
{
	kepoll_selector *es = (kepoll_selector *)selector->ctx;
	close(es->kdpfd);
	close(es->notice_st.st.fd);
	xfree(es);
}

static void epoll_selector_next(kselector *selector, KOPAQUE data, result_callback result, void *arg, int got)
{
	kepoll_selector *es = (kepoll_selector *)selector->ctx;
	kepoll_notice(&es->notice_st, data, result, arg, got);
	return;
}
static bool epoll_selector_accept(kserver_selectable* ss, void *arg)
{
	kselectable* st = &ss->st;
	kepoll_selector *es = (kepoll_selector *)st->base.selector->ctx;
	struct epoll_event ev;	
	st->e[OP_WRITE].arg = arg;
	assert(st->e[OP_READ].result == kselector_event_accept);
	KBIT_SET(st->base.st_flags,STF_READ);
	if (KBIT_TEST(st->base.st_flags,STF_RREADY)) {
		kselector_add_list(st->base.selector,st,KGL_LIST_READY);
		return true;
	}
	if (KBIT_TEST(st->base.st_flags,STF_REV)) {
		return true;
	}
	KBIT_SET(st->base.st_flags,STF_REV|STF_ET);
	ev.events = EPOLLIN|EPOLLRDHUP|EPOLLET;
	ev.data.ptr = st;
	int ret = epoll_ctl(es->kdpfd, EPOLL_CTL_ADD, st->fd, &ev);
	if (ret!=0) {
		KBIT_CLR(st->base.st_flags,STF_READ|STF_ET|STF_REV);
		return false;
	}	
	return true;
}
static bool epoll_selector_listen(kserver_selectable *ss, result_callback result)
{
	//kepoll_selector *es = (kepoll_selector *)ss->st.base.selector->ctx;	
	kselectable *st = &ss->st;
	st->e[OP_READ].arg = ss;
	st->e[OP_READ].result = kselector_event_accept;
	st->e[OP_READ].buffer = NULL;
	KBIT_SET(st->base.st_flags,STF_RREADY);	
	st->e[OP_WRITE].result = result;
	return true;
}
static bool epoll_selector_connect(kselector *selector, kselectable *st, result_callback result, void *arg)
{
	kepoll_selector *es = (kepoll_selector *)selector->ctx;
	assert(KBIT_TEST(st->base.st_flags,STF_READ|STF_WRITE|STF_RDHUP|STF_REV|STF_WEV)==0);
	st->e[OP_WRITE].arg = arg;
	st->e[OP_WRITE].result = result;
	st->e[OP_WRITE].buffer = NULL;
	KBIT_SET(st->base.st_flags,STF_WRITE);
	if (!KBIT_TEST(st->base.st_flags,STF_WEV|STF_REV)) {
		if (!epoll_add_event(es->kdpfd,st,STF_WEV|STF_REV)) {
			KBIT_CLR(st->base.st_flags,STF_WRITE);
			return false;
		}
	}
	kselector_add_list(selector,st,KGL_LIST_CONNECT);
	return true;
}
static INLINE void epoll_selector_remove(kselector *selector, kselectable *st)
{
	kepoll_selector *es = (kepoll_selector *)selector->ctx;
	if (!KBIT_TEST(st->base.st_flags,STF_REV|STF_WEV)) {
		//socket not set event
		return;
	}
	kselector_remove_list(selector,st);
	SOCKET sockfd = st->fd;
	assert(KBIT_TEST(st->base.st_flags,STF_READ|STF_WRITE|STF_RDHUP)==0);
	struct epoll_event ev;
	KBIT_CLR(st->base.st_flags,STF_REV|STF_WEV|STF_ET|STF_RREADY|STF_WREADY);
	if (epoll_ctl(es->kdpfd, EPOLL_CTL_DEL,sockfd, &ev) != 0) {
		klog(KLOG_ERR, "epoll del sockfd error: fd=%d,errno=%d\n", sockfd,errno);
		return;
	}
}

static bool epoll_selector_readhup(kselector *selector, kselectable *st, result_callback result, void *arg)
{
	kepoll_selector *es = (kepoll_selector *)selector->ctx;
	//printf("st=[%p] read_hup\n",st);
#ifdef EPOLLRDHUP
	if (KBIT_TEST(st->base.st_flags,STF_READ|STF_WRITE)) {
		return false;
	}
	KBIT_SET(st->base.st_flags,STF_RDHUP);
	st->e[OP_WRITE].arg = arg;
	st->e[OP_WRITE].result = result;
	st->e[OP_WRITE].buffer = NULL;
	if (!KBIT_TEST(st->base.st_flags,STF_WEV|STF_REV)) {
		if (!epoll_add_event(es->kdpfd,st,STF_WEV|STF_REV)) {
			KBIT_CLR(st->base.st_flags,STF_RDHUP);
			return false;
		}
	}
	return true;
#else
	return false;
#endif
}
static bool epoll_selector_remove_readhup(kselector *selector, kselectable *st)
{
#ifdef EPOLLRDHUP
	if (!KBIT_TEST(st->base.st_flags,STF_RDHUP)) {
			return true;
	}
	assert(KBIT_TEST(st->base.st_flags,STF_READ|STF_WRITE)==0);
	KBIT_CLR(st->base.st_flags,STF_RDHUP);
	//if st in ready list,remove it
	epoll_selector_remove(selector,st);
	return true;
#else
	return false;
#endif
}
static kev_result epoll_selector_read(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	kepoll_selector *es = (kepoll_selector *)selector->ctx;
	assert(KBIT_TEST(st->base.st_flags,STF_READ)==0);
	st->e[OP_READ].arg = arg;
	st->e[OP_READ].result = result;
	st->e[OP_READ].buffer = buffer;
	KBIT_SET(st->base.st_flags,STF_READ);
	KBIT_CLR(st->base.st_flags,STF_RDHUP);
	if (KBIT_TEST(st->base.st_flags,STF_RREADY)) {
		return kselectable_is_read_ready(selector, st);
	}
	if (!KBIT_TEST(st->base.st_flags,STF_REV)) {
		if (!epoll_add_event(es->kdpfd,st,STF_REV)) {
			KBIT_CLR(st->base.st_flags,STF_READ);
			return result(st->data, arg, -1);
		}
	}
	if (st->base.queue.next==NULL) {
		kselector_add_list(selector,st,KGL_LIST_RW);
	}
	return kev_ok;
}
static kev_result epoll_selector_write(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	kepoll_selector *es = (kepoll_selector *)selector->ctx;
	assert(KBIT_TEST(st->base.st_flags,STF_WRITE)==0);
	st->e[OP_WRITE].arg = arg;
	st->e[OP_WRITE].result = result;
	st->e[OP_WRITE].buffer = buffer;
	KBIT_SET(st->base.st_flags,STF_WRITE);
	KBIT_CLR(st->base.st_flags,STF_RDHUP);
	if (KBIT_TEST(st->base.st_flags,STF_WREADY)) {
		return kselectable_is_write_ready(selector, st);
	}
	if (!KBIT_TEST(st->base.st_flags,STF_WEV)) {
		if (!epoll_add_event(es->kdpfd,st,STF_REV|STF_WEV)) {
			KBIT_CLR(st->base.st_flags,STF_WRITE);
			return result(st->data,arg,-1);
		}
	}
	if (st->base.queue.next==NULL) {
		kselector_add_list(selector,st,KGL_LIST_RW);
	}
	return kev_ok;
}

static kev_result epoll_selector_sendfile(kselectable* st, result_callback result, buffer_callback buffer, void* arg) {
	kepoll_selector *es = (kepoll_selector *)st->base.selector->ctx;
	assert(!KBIT_TEST(st->base.st_flags, STF_WRITE|STF_SENDFILE));
	st->e[OP_WRITE].arg = arg;
	st->e[OP_WRITE].result = result;
	st->e[OP_WRITE].buffer = buffer;
	KBIT_SET(st->base.st_flags,STF_WRITE|STF_SENDFILE);
	KBIT_CLR(st->base.st_flags,STF_RDHUP);
	if (KBIT_TEST(st->base.st_flags,STF_WREADY)) {
		return kselectable_is_write_ready(st->base.selector, st);
	}
	if (!KBIT_TEST(st->base.st_flags,STF_WEV)) {
		if (!epoll_add_event(es->kdpfd,st,STF_REV|STF_WEV)) {
			KBIT_CLR(st->base.st_flags,STF_WRITE|STF_SENDFILE);
			return result(st->data, arg, -1);
		}
	}
	if (st->base.queue.next==NULL) {
		kselector_add_list(st->base.selector,st,KGL_LIST_RW);
	}
	return kev_ok;
}
static int epoll_selector_select(kselector *selector,int tmo) {
	struct epoll_event events[MAXEVENT];
	uint32_t ev;
	int ret = epoll_wait(((kepoll_selector *)selector->ctx)->kdpfd, events, MAXEVENT, tmo);
	if (selector->utm) {
		kselector_update_time();	
	}
	//if (ret>0) {
	//	printf("epoll_wait ret=[%d]\n",ret);
	//}
	for (int n = 0; n < ret; ++n) {
		kselectable *st = ((kselectable *) events[n].data.ptr);
		ev = events[n].events;
		bool in_ready_list = false;
#ifndef NDEBUG
		//klog(KLOG_DEBUG,"event happened st=[%p] ev=[%d]\n",st,ev);
#endif
		//if (KBIT_TEST(ev, EPOLLHUP | EPOLLERR)) {
		//	KBIT_SET(st->base.st_flags, STF_ERR);
		//}
#ifdef EPOLLRDHUP
		if (KBIT_TEST(ev,EPOLLRDHUP|EPOLLIN)==(EPOLLRDHUP|EPOLLIN)) {
			KBIT_SET(st->base.st_flags, STF_ERR);
		}
#endif
		//write ready
		if (KBIT_TEST(ev,EPOLLRDHUP)) {
			KBIT_SET(st->base.st_flags,STF_WREADY);
			if (KBIT_TEST(st->base.st_flags,STF_WRITE|STF_RDHUP)) {
				kselector_add_list(selector,st,KGL_LIST_READY);
				in_ready_list = true;
			}
		} else if (KBIT_TEST(ev,EPOLLOUT)) {
			KBIT_SET(st->base.st_flags,STF_WREADY);
			if (KBIT_TEST(st->base.st_flags,STF_WRITE)) {
				kselector_add_list(selector,st,KGL_LIST_READY);
				in_ready_list = true;
			}
		}
		//read ready
		if (KBIT_TEST(ev,EPOLLIN|EPOLLPRI|EPOLLHUP)) {
			KBIT_SET(st->base.st_flags,STF_RREADY);
			if (KBIT_TEST(st->base.st_flags,STF_READ) && !in_ready_list) {
				kselector_add_list(selector,st,KGL_LIST_READY);
			}
		}
	}
	return ret;
}
void epoll_selector_aio_open(kselector *selector,kasync_file *aio_file, FILE_HANDLE fd)
{
	aio_file->st.fd = (SOCKET)fd;
	aio_file->st.base.selector = selector;
}
bool epoll_selector_aio_write(kasync_file *file, result_callback result,const char *buf, int length, void *arg)
{
	kepoll_selector *es = (kepoll_selector *)file->st.base.selector->ctx;
	file->st.direct_io_offset = 0;
	if (file->st.direct_io) {
		file->st.direct_io_orig_length = length;
		assert(buf == (char *)kgl_align_ptr(buf,kgl_aio_align_size));
		assert(file->st.offset == kgl_align(file->st.offset, kgl_aio_align_size));
	}
#ifdef KF_ASYNC_WORKER
	file->st.e[OP_WRITE].arg = arg;
	file->st.e[OP_WRITE].result = result;
	file->kiocb.length = length;
	file->kiocb.buf = (char*)buf;
	file->kiocb.cmd = kf_aio_write;
	return kasync_file_worker_start(file);
#else
	//io_submit always use OP_READ for aio_read/aio_write.
	file->st.e[OP_READ].arg = arg;
	file->st.e[OP_READ].result = result;
	struct iocb *iocb = &file->iocb;
	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_fildes = file->st.fd;
	iocb->aio_lio_opcode = IOCB_CMD_PWRITE;
	iocb->aio_reqprio = 0;
	iocb->aio_buf = (__u64)(uintptr_t)buf;
	iocb->aio_nbytes = length;
	iocb->aio_offset = _kasync_file_get_adjust_offset(file);
	iocb->aio_flags = IOCB_FLAG_RESFD;
	iocb->aio_resfd = es->aio_st.st.fd;
	iocb->aio_data = (__u64)(uintptr_t)file;
	if (io_submit(es->aio_st.aio_ctx, 1, &iocb)==1) {
		return true;
	}
	return false;
#endif
}
bool epoll_selector_aio_read(kasync_file *file, result_callback result, char *buf, int length, void *arg)
{
	kepoll_selector *es = (kepoll_selector *)file->st.base.selector->ctx;
	if (file->st.direct_io) {
		file->st.direct_io_orig_length = length;
		assert(buf == (char *)kgl_align_ptr(buf,kgl_aio_align_size));
		int64_t new_offset = kgl_align_floor(file->st.offset,kgl_aio_align_size);
		int new_length = kgl_align(length,kgl_aio_align_size);
		if (new_length==0) {
			new_length = kgl_aio_align_size;			
		}
		length = new_length;
		file->st.direct_io_offset = (uint16_t)(file->st.offset - new_offset);
	} else {
		file->st.direct_io_offset = 0;
	}
	file->st.e[OP_READ].arg = arg;
	file->st.e[OP_READ].result = result;
#ifdef KF_ASYNC_WORKER
	file->kiocb.length = length;
	file->kiocb.buf = (char*)buf;
	file->kiocb.cmd = kf_aio_read;
	return kasync_file_worker_start(file);
#else
	struct iocb *iocb = &file->iocb;	
	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_fildes = file->st.fd;
	iocb->aio_lio_opcode = IOCB_CMD_PREAD;
	iocb->aio_reqprio = 0;
	iocb->aio_buf = (__u64)(uintptr_t)buf;
	iocb->aio_nbytes = length;
	iocb->aio_offset = _kasync_file_get_adjust_offset(file);
	iocb->aio_flags = IOCB_FLAG_RESFD;
	iocb->aio_resfd = es->aio_st.st.fd;
	iocb->aio_data = (__u64)(uintptr_t)file;
	//printf("read set iocb=[%p]\n",iocb);
	if (io_submit(es->aio_st.aio_ctx, 1, &iocb)==1) {
		return true;
	}
	perror("io_submit read");
	return false;
#endif
}
static kselector_module epoll_selector_module = {
	"epoll",
	epoll_selector_init,
	epoll_selector_destroy,
	kselector_default_bind,
	epoll_selector_listen,
	epoll_selector_accept,
	epoll_selector_connect,
	epoll_selector_remove,
	epoll_selector_read,
	epoll_selector_write,
	epoll_selector_readhup,
	epoll_selector_remove_readhup,
	epoll_selector_select,
	epoll_selector_next,
	epoll_selector_aio_open,
	epoll_selector_aio_write,
	epoll_selector_aio_read,
	epoll_selector_sendfile
};
void kepoll_module_init() {
	kgl_selector_module = epoll_selector_module;
}
#endif
void kepoll_notice_init(kselector *selector,kepoll_notice_selectable *notice_st,result_callback result,void *arg)
{
	kmutex_init(&notice_st->lock,NULL);
	notice_st->st.fd = eventfd(0, EFD_CLOEXEC);
	if (notice_st->st.fd == -1) {
		perror("eventfd");
	}
	notice_st->st.base.selector = selector;
	notice_st->st.e[OP_READ].arg = arg;
	notice_st->st.e[OP_READ].result = result;
	notice_st->st.e[OP_READ].buffer = NULL;
}

#endif

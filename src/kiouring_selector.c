#include "kfeature.h"
#include "kmalloc.h"
#include "kepoll_selector.h"
#include "kiouring_selector.h"
#ifdef LINUX
#ifdef LINUX_IOURING
#include "kserver.h"
#include "ksocket.h"
#include "kasync_file.h"
#include "klog.h"
#include <liburing.h>
#include <poll.h>
#include "kfiber.h"

#define URING_COUNT 128
#define MAXSENDBUF  32


static unsigned URING_MASK;
typedef struct {
    struct io_uring ring;
	kepoll_notice_selectable notice_st;
	WSABUF bufs[URING_COUNT][MAXSENDBUF];
	unsigned buf_index;
} kiouring_selector;
static int null_buffer(KOPAQUE data, void *arg,LPWSABUF buf,int bc)
{
	//never go here;
	assert(false);
	return 0;
}
WSABUF *kiouring_get_bufs(kiouring_selector *cs)
{
	WSABUF *bufs = cs->bufs[cs->buf_index & URING_MASK];
	cs->buf_index++;
	return bufs;
}
static struct io_uring_sqe *kiouring_get_seq(struct io_uring *ring)
{
	struct io_uring_sqe *sqe;
	int ret;
	sqe = io_uring_get_sqe(ring);
	if (sqe) {
		return sqe;
	}
	/*
	* If the SQ ring is full, we may need to submit IO first
	*/
	ret = io_uring_submit(ring);
	if (ret < 0) {
		return NULL;
	}
	sqe = io_uring_get_sqe(ring);
	return sqe;
}
static bool kiouring_add_poll(struct io_uring *ring,kselectable *st,kgl_event *e,short poll_mask)
{
	e->st = st;
	struct io_uring_sqe *sqe = kiouring_get_seq(ring);
	if (sqe==NULL) {
		return false;
	}
	io_uring_prep_poll_add(sqe, st->fd,poll_mask);
	io_uring_sqe_set_data(sqe, e);
	return true;
}
static bool kiouring_add_event(struct io_uring *ring,kselectable *st,uint16_t ev)
{
	if (KBIT_TEST(ev,STF_READ)) {		
		if (!kiouring_add_poll(ring,st,&st->e[OP_READ],POLLIN)) {
			return false;
		}
		KBIT_SET(st->st_flags,STF_READ);
	}
	if (KBIT_TEST(ev,STF_WRITE)) {		
		if (!kiouring_add_poll(ring,st,&st->e[OP_WRITE],POLLOUT)) {
			return false;
		}
		KBIT_SET(st->st_flags,STF_WRITE);
	}
	return true;
}
static kev_result kiouring_notice_event(KOPAQUE data, void *arg,int got)
{
	if (got<0) {
		klog(KLOG_ERR,"BUG!!! iouring notice event result failed got=[%d]\n",got);
		return kev_err;
	}
	kiouring_selector *ctx = (kiouring_selector *)arg; 
	kepoll_notice_event(&ctx->notice_st);
	if (!kiouring_add_event(&ctx->ring,&ctx->notice_st.st,STF_READ)) {
		klog(KLOG_ERR,"BUG!!! iouring add notice event failed.\n");
	}
	return kev_ok;
}
bool kiouring_is_support()
{
	struct io_uring_probe *probe = io_uring_get_probe();
	if (probe==NULL) {
		fprintf(stderr,"cann't get io_uring probe\n");
		return false;
	}
	//printf("io_uring last_op=[%d]\n",probe->last_op);
	if (!io_uring_opcode_supported(probe, IORING_OP_ACCEPT)) {
		free(probe);
		return false;
	}
	return true;
}
static void iouring_selector_init(kselector *selector)
{
	kiouring_selector *ctx = xmemory_new(kiouring_selector);
	memset(ctx,0,sizeof(kiouring_selector));
	int ret;
	ret = io_uring_queue_init(URING_COUNT, &ctx->ring, 0);
	if (ret < 0) {
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
		abort();
	}
	kassert(*ctx->ring.sq.kring_mask == URING_COUNT - 1);
	kepoll_notice_init(selector,&ctx->notice_st,kiouring_notice_event,ctx);
	kiouring_add_event(&ctx->ring,&ctx->notice_st.st,STF_READ);
	selector->ctx = (void *)ctx;
}
static void iouring_selector_destroy(kselector *selector)
{
	kiouring_selector *es = (kiouring_selector *)selector->ctx;
	xfree(es);
}
static void iouring_selector_next(kselector *selector, KOPAQUE data, result_callback result, void *arg, int got)
{
	kiouring_selector *es = (kiouring_selector *)selector->ctx;
	kepoll_notice(&es->notice_st,data, result,arg,got);
}

static bool iouring_add_accept_event(kselector *selector,kserver_selectable *ss,kgl_event *e)
{
	kiouring_selector *cs = (kiouring_selector *)selector->ctx;
	struct io_uring_sqe *sqe = kiouring_get_seq(&cs->ring);
	if (sqe==NULL) {
		return false;
	}
	KBIT_SET(ss->st.st_flags,STF_READ);
	ss->addr_len = (socklen_t)ksocket_addr_len(&ss->accept_addr);
	io_uring_prep_accept(sqe, e->st->fd,(struct sockaddr *)&ss->accept_addr,&ss->addr_len,SOCK_CLOEXEC);
	io_uring_sqe_set_data(sqe, e);
	return true;

}
static kev_result iouring_listen_result(KOPAQUE data, void *arg,int got)
{
	kserver_selectable *ss = (kserver_selectable *)arg;
	kselectable *st = &ss->st;
	if (got<0) {
		klog(KLOG_ERR,"iouring accept failed. error=[%d]\n",got);
		ksocket_init(got);
	}
	kev_result ret = st->e[OP_WRITE].result(st->data, st->e[OP_WRITE].arg,got);
	if (!KEV_AVAILABLE(ret)) {
		return ret;
	}
	if (!iouring_add_accept_event(st->selector,ss,&st->e[OP_READ])) {
		klog(KLOG_ERR,"add accept event failed\n");
	}
	return kev_ok;
}
static bool iouring_selector_listen(kselector *selector, kserver_selectable *ss, result_callback result)
{
	//printf("*****listen now\n");
	
	kselectable *st = &ss->st;
	kgl_event *e = &st->e[OP_READ];
	e->arg = ss;
	e->result = iouring_listen_result;
	e->buffer = NULL;
	e->st = st;
	
	st->e[OP_WRITE].arg = ss;
	st->e[OP_WRITE].result = result;
	KBIT_CLR(st->st_flags,STF_WRITE|STF_RDHUP);
	return iouring_add_accept_event(selector,ss,e);
}
static bool iouring_selector_read(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	kiouring_selector *cs = (kiouring_selector *)selector->ctx;
	struct io_uring_sqe *sqe = kiouring_get_seq(&cs->ring);
	if (sqe==NULL) {
		return false;
	}
	kassert(KBIT_TEST(st->st_flags, STF_READ) == 0);	
	kgl_event *e = &st->e[OP_READ];
	e->arg = arg;
	e->result = result;
	e->st = st;
	if (buffer) {
		e->buffer = buffer;
		WSABUF *bufs = kiouring_get_bufs(cs);
		int bc = buffer(st->data, arg, bufs, MAXSENDBUF);
		io_uring_prep_readv(sqe,st->fd,bufs,bc,0);
	} else {
		e->buffer = null_buffer;
		io_uring_prep_poll_add(sqe, st->fd,POLLIN);
	}
	io_uring_sqe_set_data(sqe, e);
	KBIT_SET(st->st_flags,STF_READ);
	if (st->queue.next == NULL) {
		kselector_add_list(selector, st, KGL_LIST_RW);
	}
	return true;
}

static bool iouring_selector_write(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	kiouring_selector *cs = (kiouring_selector *)selector->ctx;
	struct io_uring_sqe *sqe = kiouring_get_seq(&cs->ring);
	if (sqe==NULL) {
		return false;
	}
	kgl_event *e = &st->e[OP_WRITE];
	e->arg = arg;
	e->result = result;
	e->st = st;	
	
	if (buffer) {
		e->buffer = buffer;
		WSABUF *bufs = kiouring_get_bufs(cs);
		int bc = buffer(st->data, arg, bufs, MAXSENDBUF);
		kassert(bufs[0].iov_len > 0);
		io_uring_prep_writev(sqe,st->fd,bufs,bc,0);
	} else {
		e->buffer = null_buffer;
		io_uring_prep_poll_add(sqe, st->fd,POLLOUT);
	}	
	io_uring_sqe_set_data(sqe, e);
	KBIT_SET(st->st_flags,STF_WRITE);
	if (st->queue.next == NULL) {
		kselector_add_list(selector, st, KGL_LIST_RW);
	}
	return true;
	
}
void iouring_selector_aio_open(kselector *selector, kasync_file *aio_file, FILE_HANDLE fd)
{
	aio_file->st.fd = (SOCKET)fd;
	aio_file->st.selector = selector;
	return;
}

bool iouring_selector_aio_write(kselector *selector, kasync_file *file, char *buf, int64_t offset, int length, aio_callback cb, void *arg)
{
	kassert(kfiber_check_file_callback(cb));
	file->buf = buf;
	file->arg = arg;
	file->cb = cb;
	kiouring_selector *cs = (kiouring_selector *)selector->ctx;
	struct io_uring_sqe *sqe = kiouring_get_seq(&cs->ring);
	if (sqe==NULL) {
		return false;
	}
	katom_inc((void *)&kgl_aio_count);
	kselectable *st = &file->st;
	kassert(KBIT_TEST(st->st_flags, STF_WRITE) == 0);
	kgl_event *e = &st->e[OP_WRITE];
	e->arg = file;
	e->result = result_async_file_event;
	e->buffer = NULL;
	e->st = st;
	WSABUF *bufs = kiouring_get_bufs(cs);
	bufs[0].iov_base = buf;
	bufs[0].iov_len = length;
	io_uring_prep_writev(sqe,st->fd,bufs,1,offset);
	io_uring_sqe_set_data(sqe, e);
	KBIT_SET(st->st_flags,STF_WRITE);
	return true;
}
bool iouring_selector_aio_read(kselector *selector, kasync_file *file, char *buf, int64_t offset, int length, aio_callback cb, void *arg)
{
	kassert(kfiber_check_file_callback(cb));
	file->buf = buf;
	file->arg = arg;
	file->cb = cb;
	kiouring_selector *cs = (kiouring_selector *)selector->ctx;
	struct io_uring_sqe *sqe = kiouring_get_seq(&cs->ring);
	if (sqe==NULL) {
		return false;
	}
	katom_inc((void *)&kgl_aio_count);
	kselectable *st = &file->st;
	kassert(KBIT_TEST(st->st_flags, STF_READ) == 0);	
	kgl_event *e = &st->e[OP_READ];
	e->arg = file;
	e->result = result_async_file_event;
	e->buffer = NULL;
	e->st = st;
	WSABUF *bufs = kiouring_get_bufs(cs);
	bufs[0].iov_base = buf;
	bufs[0].iov_len = length;
	io_uring_prep_readv(sqe,st->fd,bufs,1,offset);
	io_uring_sqe_set_data(sqe, e);
	KBIT_SET(st->st_flags,STF_READ);
	return true;
}
static bool iouring_selector_connect(kselector *selector, kselectable *st, result_callback result, void *arg)
{
	//printf("connection st=[%p]\n", st);
	kassert(KBIT_TEST(st->st_flags, STF_WRITE) == 0);
	kiouring_selector *cs = (kiouring_selector *)selector->ctx;
	struct io_uring_sqe *sqe = kiouring_get_seq(&cs->ring);
	if (sqe==NULL) {
		return false;
	}
	WSABUF addr_buf;
	st->e[OP_READ].buffer(st->data, st->e[OP_READ].arg, &addr_buf, 1);
	KBIT_SET(st->st_flags,STF_WRITE);
	kgl_event *e = &st->e[OP_WRITE];
	e->arg = arg;
	e->result = result;
	e->buffer = NULL;
	e->st = st;
	io_uring_prep_connect(sqe, st->fd,(struct sockaddr *)addr_buf.iov_base,(socklen_t)addr_buf.iov_len);
	io_uring_sqe_set_data(sqe, e);
	kselector_add_list(selector,st, KGL_LIST_CONNECT);
	return true;
}
static bool iouring_selector_recvfrom(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, buffer_callback addr_buffer, void *arg)
{
#if 0
	kiouring_selector *es = (kiouring_selector *)selector->ctx;
	assert(KBIT_TEST(st->st_flags,STF_READ|STF_WRITE|STF_RECVFROM)==0);
	st->e[OP_READ].arg = arg;
	st->e[OP_READ].result = result;
	st->e[OP_READ].buffer = buffer;
	st->e[OP_WRITE].buffer = addr_buffer;
	KBIT_SET(st->st_flags,STF_RECVFROM);
	if (KBIT_TEST(st->st_flags,STF_RREADY)) {
		kselector_add_list(selector,st,KGL_LIST_READY);
		return true;
	}
	if (!KBIT_TEST(st->st_flags,STF_REV)) {
		if (!epoll_add_event(es->kdpfd,st,STF_REV)) {
			KBIT_CLR(st->st_flags,STF_RECVFROM);
			return false;
		}
	}
	if (st->queue.next==NULL) {
		kselector_add_list(selector,st,KGL_LIST_RW);
	}
	return true;
#endif
	return false;
}
static void iouring_add_timeout(struct io_uring *ring,unsigned wait_nr,struct __kernel_timespec *ts)
{
	struct io_uring_sqe *sqe = kiouring_get_seq(ring);
	io_uring_prep_timeout(sqe, ts, wait_nr, 0);
	sqe->user_data = LIBURING_UDATA_TIMEOUT;
}
static inline void handle_complete_event(kselector *selector,kgl_event *e,int got,uint32_t flags)
{
	//printf("st=[%p] got=[%d],flags=[%d]\n",e,got,flags);
	kselectable *st = e->st;
	kassert(st);
	if (KBIT_TEST(st->st_flags, STF_READ | STF_WRITE) == (STF_READ | STF_WRITE)) {
		//reset active_msec
		if (!KBIT_TEST(st->st_flags, STF_RREADY2 | STF_WREADY2)) {
			kselector_add_list(selector, st, KGL_LIST_RW);
		}
	} else {
		kselector_remove_list(selector,st);
	}
	if (got>0 && e->buffer==null_buffer) {
		//如果只是检测pollout/pollin事件，成功后，把 got设置为0，使上层接口和epoll/iocp/kqueue等表现一致。
		got = 0;
	}
	if (e == &st->e[OP_READ]) {
		//printf("handle read event st=[%p]\n", st);
		kassert(KBIT_TEST(st->st_flags, STF_READ|STF_RECVFROM));
		KBIT_CLR(st->st_flags, STF_READ|STF_RECVFROM);
		kassert(!KBIT_TEST(st->st_flags, STF_RREADY|STF_RREADY2));		
	} else 	if (e == &st->e[OP_WRITE]) {
		//printf("handle write event st=[%p]\n", st);
		kassert(KBIT_TEST(st->st_flags, STF_WRITE));
		KBIT_CLR(st->st_flags, STF_WRITE);
		kassert(!KBIT_TEST(st->st_flags, STF_WREADY|STF_WREADY2));
	} else {
		kassert(false);
	}
	e->result(st->data, e->arg, got);
	return;

}
static int iouring_handle_cq(kselector *selector,struct io_uring *ring,int count)
{
	struct io_uring_cq *cq = &ring->cq;
	unsigned head = *cq->khead;
	unsigned last = io_uring_smp_load_acquire(ring->cq.ktail);
	unsigned mask = *cq->kring_mask;
	struct io_uring_cqe *cqe;
	int result = 0;
	for (;head != last; head++) {
		cqe = &cq->cqes[head & mask];
		if (cqe->user_data == LIBURING_UDATA_TIMEOUT) {
			continue;
		}
		handle_complete_event(selector,(kgl_event *)io_uring_cqe_get_data(cqe),cqe->res,cqe->flags);
		result ++;
	}
	io_uring_smp_store_release(cq->khead, head);
	return result;
}
static void iouring_selector_select(kselector *selector)
{
	kiouring_selector *es = (kiouring_selector *)selector->ctx;
	struct __kernel_timespec tm;
	memset(&tm,0,sizeof(tm));
	tm.tv_sec = SELECTOR_TMO_MSEC/1000;
	tm.tv_nsec = SELECTOR_TMO_MSEC * 1000 - tm.tv_sec * 1000000;
	int result = 0;
	for (;;) {
#ifdef MALLOCDEBUG
        if (kselector_can_close(selector)) {
                return;
        }
#endif
		kselector_check_timeout(selector,(int)result);
        iouring_add_timeout(&es->ring,1,&tm);
		int n = io_uring_submit_and_wait(&es->ring, 1);
		if (selector->utm) {
			kselector_update_time();
		}
		result = iouring_handle_cq(selector,&es->ring,n);		
	}
}
static kselector_module iouring_selector_module = {
	"iouring",
	iouring_selector_init,
	iouring_selector_destroy,
	kselector_default_bind,
	iouring_selector_listen,
	iouring_selector_connect,
	kselector_default_remove,
	iouring_selector_read,
	iouring_selector_write,
	kselector_default_readhup,
	kselector_default_remove_readhup,
	iouring_selector_recvfrom,
	iouring_selector_select,
	iouring_selector_next,

	iouring_selector_aio_open,
	iouring_selector_aio_write,
	iouring_selector_aio_read
};

void kiouring_module_init()
{
	URING_MASK = URING_COUNT - 1;
    kgl_selector_module = iouring_selector_module;
}
#endif
#endif

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

typedef struct {
	kselectable *st;
	kasync_file *file;
	int pipe[2];
	int refs;
	int got;
	bool skip_call_result;
} iouring_sendfile;

static unsigned URING_MASK;
typedef struct {
    struct io_uring ring;
	kepoll_notice_selectable notice_st;
	WSABUF bufs[URING_COUNT][MAX_IOVECT_COUNT];
	unsigned buf_index;
} kiouring_selector;

static kev_result iouring_sendfile_result(iouring_sendfile *sf,int got, bool final_result) {
	if (final_result) {
		sf->got = got;
	}
	sf->refs--;
	if (sf->refs>0) {
		return kev_ok;
	}
	kev_result ret = kev_destroy;
	if (!sf->skip_call_result) {
	 	ret = sf->file->st.e[OP_WRITE].result(sf->st->data, sf->file->st.e[OP_WRITE].arg, sf->got);
	}
	if (sf->pipe[0]>0) {
		close(sf->pipe[0]);
	}
	if (sf->pipe[1]>0) {
		close(sf->pipe[1]);
	}
	xfree(sf);
	return ret;
}
static kev_result iouring_sendfile_selectable_result(KOPAQUE data, void *arg,int got) {
	iouring_sendfile *sf = (iouring_sendfile *)arg;
	close(sf->pipe[0]);
	sf->pipe[0] = -1;
	return iouring_sendfile_result(sf,got,true);
}
static kev_result iouring_sendfile_file_result(KOPAQUE data, void *arg,int got) {
	iouring_sendfile *sf = (iouring_sendfile *)arg;
	close(sf->pipe[1]);
	sf->pipe[1] = -1;
	return iouring_sendfile_result(sf,got,false);
}
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
		KBIT_SET(st->base.st_flags,STF_READ);
	}
	if (KBIT_TEST(ev,STF_WRITE)) {		
		if (!kiouring_add_poll(ring,st,&st->e[OP_WRITE],POLLOUT)) {
			return false;
		}
		KBIT_SET(st->base.st_flags,STF_WRITE);
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
	if (!io_uring_opcode_supported(probe, IORING_OP_SPLICE)) {
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
	KBIT_SET(ss->st.base.st_flags,STF_READ);
	ss->addr_len = (socklen_t)ksocket_addr_len(&ss->accept_addr);
	io_uring_prep_accept(sqe, e->st->fd,(struct sockaddr *)&ss->accept_addr,&ss->addr_len,SOCK_CLOEXEC);
	io_uring_sqe_set_data(sqe, e);
	return true;

}
static kev_result iouring_listen_result(KOPAQUE data, void *arg,int got)
{
	kserver_selectable *ss = (kserver_selectable *)arg;
	kselectable *st = &ss->st;
	if (got<0) {
		//klog(KLOG_ERR,"iouring accept failed. error=[%d]\n",got);
		ksocket_init(got);
	}
	return st->e[OP_WRITE].result(st->data, st->e[OP_WRITE].arg,got);	
}
static bool iouring_selector_accept(kserver_selectable* ss, void *arg)
{
	kselectable *st = &ss->st;
	st->e[OP_WRITE].arg = arg;
	kgl_event *e = &st->e[OP_READ];
	return iouring_add_accept_event(st->base.selector,ss,e);
}
static bool iouring_selector_listen(kserver_selectable *ss, result_callback result)
{
	//printf("*****listen now\n");	
	kselectable *st = &ss->st;
	kgl_event *e = &st->e[OP_READ];
	e->arg = ss;
	e->result = iouring_listen_result;
	e->buffer = NULL;
	e->st = st;	
	
	st->e[OP_WRITE].result = result;
	KBIT_CLR(st->base.st_flags,STF_WRITE|STF_RDHUP);
	return true;
	//return iouring_add_accept_event(selector,ss,e);
}
static bool iouring_selector_read(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	struct io_uring_sqe *sqe;
	kiouring_selector *cs = (kiouring_selector *)selector->ctx;
	kassert(KBIT_TEST(st->base.st_flags, STF_READ) == 0);	
	kgl_event *e = &st->e[OP_READ];
	e->arg = arg;
	e->result = result;
	e->st = st;
	e->buffer = buffer;
	if (KBIT_TEST(st->base.st_flags, STF_USEPOLL)) {
		if (KBIT_TEST(st->base.st_flags,STF_RREADY)) {
			KBIT_SET(st->base.st_flags,STF_READ);
			kselector_add_list(selector, st, KGL_LIST_READY);
			return true;
		}
		sqe = kiouring_get_seq(&cs->ring);
		if (sqe==NULL) {
			return false;
		}
		io_uring_prep_poll_add(sqe, st->fd, POLLIN);
		goto prepare_done;
	}
	sqe = kiouring_get_seq(&cs->ring);
	if (sqe==NULL) {
		return false;
	}
	if (buffer) {
		e->buffer = buffer;
		WSABUF *bufs = kiouring_get_bufs(cs);
		int bc = buffer(st->data, arg, bufs, MAX_IOVECT_COUNT);
		io_uring_prep_readv(sqe,st->fd,bufs,bc,0);
	} else {
		e->buffer = null_buffer;
		io_uring_prep_poll_add(sqe, st->fd,POLLIN);
	}	
prepare_done:
	KBIT_SET(st->base.st_flags,STF_READ);
	io_uring_sqe_set_data(sqe, e);
	if (st->base.queue.next == NULL) {
		kselector_add_list(selector, st, KGL_LIST_RW);
	}
	return true;
}

static bool iouring_selector_write(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	struct io_uring_sqe *sqe;
	kiouring_selector *cs = (kiouring_selector *)selector->ctx;
	kgl_event *e = &st->e[OP_WRITE];
	e->arg = arg;
	e->result = result;
	e->st = st;
	if (KBIT_TEST(st->base.st_flags, STF_USEPOLL)) {
		e->buffer = buffer;
		if (KBIT_TEST(st->base.st_flags,STF_WREADY)) {
			KBIT_SET(st->base.st_flags,STF_WRITE);
			kselector_add_list(selector, st, KGL_LIST_READY);
			return true;
		}
		sqe = kiouring_get_seq(&cs->ring);
		if (sqe==NULL) {
			return false;
		}
		io_uring_prep_poll_add(sqe, st->fd, POLLOUT);
		goto prepare_done;
	}
 	sqe = kiouring_get_seq(&cs->ring);
	if (sqe==NULL) {
		return false;
	}
	if (buffer) {
		e->buffer = buffer;
		WSABUF *bufs = kiouring_get_bufs(cs);
		int bc = buffer(st->data, arg, bufs, MAX_IOVECT_COUNT);
		kassert(bufs[0].iov_len > 0);
		io_uring_prep_writev(sqe,st->fd,bufs,bc,0);
	} else {
		e->buffer = null_buffer;
		io_uring_prep_poll_add(sqe, st->fd,POLLOUT);
	}	
prepare_done:
	KBIT_SET(st->base.st_flags,STF_WRITE);
	io_uring_sqe_set_data(sqe, e);	
	if (st->base.queue.next == NULL) {
		kselector_add_list(selector, st, KGL_LIST_RW);
	}
	return true;
	
}
void iouring_selector_aio_open(kselector *selector, kasync_file *aio_file, FILE_HANDLE fd)
{
	aio_file->st.fd = (SOCKET)fd;
	aio_file->st.base.selector = selector;
	return;
}

bool iouring_selector_aio_write(kasync_file *file, result_callback result, const char *buf, int length, void *arg)
{
	kiouring_selector *cs = (kiouring_selector *)file->st.base.selector->ctx;
	struct io_uring_sqe *sqe = kiouring_get_seq(&cs->ring);
	if (sqe==NULL) {
		return false;
	}
	kselectable *st = &file->st;
	kassert(KBIT_TEST(st->base.st_flags, STF_WRITE) == 0);
	kgl_event *e = &st->e[OP_WRITE];
	e->arg = file;
	e->result = result;
	e->buffer = NULL;
	e->st = st;
	WSABUF *bufs = kiouring_get_bufs(cs);
	bufs[0].iov_base = (void *)buf;
	bufs[0].iov_len = length;
	io_uring_prep_writev(sqe,st->fd,bufs,1,file->st.offset);
	io_uring_sqe_set_data(sqe, e);
	KBIT_SET(st->base.st_flags, STF_WRITE);
	return true;
}
bool iouring_selector_aio_read(kasync_file *file, result_callback result, char *buf, int length, void *arg)
{
	kiouring_selector *cs = (kiouring_selector *)file->st.base.selector->ctx;
	struct io_uring_sqe *sqe = kiouring_get_seq(&cs->ring);
	if (sqe==NULL) {
		return false;
	}
	kselectable *st = &file->st;
	kassert(KBIT_TEST(st->base.st_flags, STF_READ) == 0);	
	kgl_event *e = &st->e[OP_READ];
	e->arg = file;
	e->result = result;
	e->buffer = NULL;
	e->st = st;
	WSABUF *bufs = kiouring_get_bufs(cs);
	bufs[0].iov_base = buf;
	bufs[0].iov_len = length;
	io_uring_prep_readv(sqe,st->fd,bufs,1,file->st.offset);
	io_uring_sqe_set_data(sqe, e);
	KBIT_SET(st->base.st_flags,STF_READ);
	return true;
}
static bool iouring_selector_connect(kselector *selector, kselectable *st, result_callback result, void *arg)
{
	//printf("connection st=[%p]\n", st);
	kassert(KBIT_TEST(st->base.st_flags, STF_WRITE) == 0);
	kiouring_selector *cs = (kiouring_selector *)selector->ctx;
	struct io_uring_sqe *sqe = kiouring_get_seq(&cs->ring);
	if (sqe==NULL) {
		return false;
	}
	WSABUF addr_buf;
	st->e[OP_READ].buffer(st->data, st->e[OP_READ].arg, &addr_buf, 1);
	KBIT_SET(st->base.st_flags,STF_WRITE);
	kgl_event *e = &st->e[OP_WRITE];
	e->arg = arg;
	e->result = result;
	e->buffer = NULL;
	e->st = st;
	io_uring_prep_connect(sqe, st->fd,(struct sockaddr *)addr_buf.iov_base,(socklen_t)addr_buf.iov_len);
	io_uring_sqe_set_data(sqe, e);
	kselector_add_list(selector,st, KGL_LIST_CONNECT);
	return true;
}
static KASYNC_IO_RESULT iouring_selector_recvmsg(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	kiouring_selector *cs = (kiouring_selector *)selector->ctx;
	assert(KBIT_TEST(st->base.st_flags,STF_READ)==0);
	struct io_uring_sqe *sqe;
	kgl_event *e = &st->e[OP_READ];
	e->arg = arg;
	e->result = result;
	e->st = st;
	e->buffer = buffer;
	assert(KBIT_TEST(st->base.st_flags,STF_UDP));
	int got = selectable_recvmsg(st);
	if (got>=0) {
		return got;
	}
	switch (errno) {
	case EAGAIN:
		KBIT_SET(st->base.st_flags,STF_READ);
		e->buffer = null_buffer;
		sqe = kiouring_get_seq(&cs->ring);
		if (sqe==NULL) {
			KBIT_CLR(st->base.st_flags,STF_READ);
			return KASYNC_IO_ERR_SYS;
		}
		io_uring_prep_poll_add(sqe, st->fd,POLLIN);
		io_uring_sqe_set_data(sqe, e);
		if (st->base.queue.next==NULL) {
			kselector_add_list(selector,st,KGL_LIST_RW);
		}
		return KASYNC_IO_PENDING;
	case EINTR:
	case ENOMEM:
		return KASYNC_IO_ERR_BUFFER;
	default:
		return KASYNC_IO_ERR_SYS;
	}
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
	if (KBIT_TEST(st->base.st_flags, STF_READ | STF_WRITE) == (STF_READ | STF_WRITE)) {
		//reset active_msec
		if (!KBIT_TEST(st->base.st_flags, STF_RREADY2 | STF_WREADY2)) {
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
		kassert(KBIT_TEST(st->base.st_flags, STF_READ));
#ifndef ENABLE_KSSL_BIO
		if (KBIT_TEST(st->base.st_flags, STF_USEPOLL)) {
			KBIT_SET(st->base.st_flags,STF_RREADY);
			kselector_add_list(selector,st,KGL_LIST_READY);
			return;
		}
#endif
		KBIT_CLR(st->base.st_flags, STF_READ);
		kassert(!KBIT_TEST(st->base.st_flags, STF_RREADY|STF_RREADY2));
	} else 	if (e == &st->e[OP_WRITE]) {
		//printf("handle write event st=[%p]\n", st);
		kassert(KBIT_TEST(st->base.st_flags, STF_WRITE));
#ifndef ENABLE_KSSL_BIO
		if (KBIT_TEST(st->base.st_flags, STF_USEPOLL)) {
			KBIT_SET(st->base.st_flags,STF_WREADY);
			kselector_add_list(selector, st, KGL_LIST_READY);
			return;
		}
#endif
		KBIT_CLR(st->base.st_flags, STF_WRITE);
		kassert(!KBIT_TEST(st->base.st_flags, STF_WREADY|STF_WREADY2));
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
static int iouring_selector_select(kselector *selector, int tmo)
{
	kiouring_selector *es = (kiouring_selector *)selector->ctx;
	struct __kernel_timespec tm;
	memset(&tm,0,sizeof(tm));
	tm.tv_sec = tmo / 1000;
	tm.tv_nsec = tmo * 1000 - tm.tv_sec * 1000000;
	iouring_add_timeout(&es->ring,1,&tm);
	int n = io_uring_submit_and_wait(&es->ring, 1);
	if (selector->utm) {
		kselector_update_time();
	}
	return iouring_handle_cq(selector,&es->ring,n);
}
static bool iouring_selector_sendfile(kselectable* st, result_callback result, buffer_callback buffer, void* arg) {
	kiouring_selector *cs = (kiouring_selector *)st->base.selector->ctx;
	kgl_event *e;
	struct io_uring_sqe *sqe;
	if (KBIT_TEST(st->base.st_flags, STF_USEPOLL)) {
		/* ssl sendfile may use poll model */
		e = &st->e[OP_WRITE];
		e->arg = arg;
		e->result = result;
		e->st = st;
		e->buffer = buffer;
		KBIT_SET(st->base.st_flags,STF_WRITE|STF_SENDFILE);
		KBIT_CLR(st->base.st_flags,STF_RDHUP);
		if (KBIT_TEST(st->base.st_flags,STF_WREADY)) {
			kselector_add_list(st->base.selector, st, KGL_LIST_READY);
			return true;
		}
		sqe = kiouring_get_seq(&cs->ring);
		if (unlikely(sqe==NULL)) {
			KBIT_CLR(st->base.st_flags,STF_WRITE|STF_SENDFILE);
			return false;
		}
		io_uring_prep_poll_add(sqe, st->fd, POLLOUT);
	} else {
		WSABUF bufs;
		sqe = kiouring_get_seq(&cs->ring);
		if (unlikely(sqe==NULL)) {
			return false;
		}
		iouring_sendfile *sf = (iouring_sendfile *)xmalloc(sizeof(iouring_sendfile));
		memset(sf,0,sizeof(iouring_sendfile));
		if (pipe2(sf->pipe,O_CLOEXEC)!=0) {
			xfree(sf);
			return false;
		}
		buffer(st->data, arg, &bufs, 1);
		kassert(bufs.iov_len > 0);
		kasync_file *file = (kasync_file *)bufs.iov_base;
		sf->st = st;
		sf->file = file;
		sf->refs=1;
		e = &file->st.e[OP_WRITE];
		/* store final result */
		e->arg = arg;
		e->result = result;
		e->st = st;
		/* splice file to pipe */
		e = &file->st.e[OP_READ];
		e->arg = sf;
		e->result = iouring_sendfile_file_result;
		e->st = &file->st;
		io_uring_prep_splice(sqe,file->st.fd,file->st.offset,sf->pipe[1],-1,bufs.iov_len,0);
		io_uring_sqe_set_data(sqe, e);
		KBIT_SET(file->st.base.st_flags,STF_READ);
		/* splice pipe to socket */
		sqe = kiouring_get_seq(&cs->ring);
		if (sqe==NULL) {
			sf->skip_call_result = true;
			return false;
		}
		sf->refs++;
		e = &st->e[OP_WRITE];
		e->arg = sf;
		e->result = iouring_sendfile_selectable_result;
		e->st = st;
		io_uring_prep_splice(sqe,sf->pipe[0],-1,st->fd,-1,bufs.iov_len,0);
		KBIT_SET(st->base.st_flags,STF_WRITE);
	}
	io_uring_sqe_set_data(sqe, e);
	if (st->base.queue.next == NULL) {
		kselector_add_list(st->base.selector, st, KGL_LIST_RW);
	}
	return true;
}
void iouring_selector_bind(kselector *selector, kselectable *st)
{
	st->base.selector = selector;
	for (int i=0;i<2;i++) {
		st->e[i].st = st;
	}
}
static kselector_module iouring_selector_module = {
	"iouring",
	iouring_selector_init,
	iouring_selector_destroy,
	iouring_selector_bind,
	iouring_selector_listen,
	iouring_selector_accept,
	iouring_selector_connect,
	kselector_default_remove,
	iouring_selector_read,
	iouring_selector_write,
	kselector_default_readhup,
	kselector_default_remove_readhup,
	iouring_selector_recvmsg,
	iouring_selector_select,
	iouring_selector_next,

	iouring_selector_aio_open,
	iouring_selector_aio_write,
	iouring_selector_aio_read,
	iouring_selector_sendfile
};

void kiouring_module_init()
{
	URING_MASK = URING_COUNT - 1;
    kgl_selector_module = iouring_selector_module;
}
#endif
#endif

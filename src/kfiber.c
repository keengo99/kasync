#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include "kfiber.h"
#include "kmalloc.h"
#include "kasync_worker.h"
#include "kselector_manager.h"
#include "kaddr.h"
#include "kmalloc.h"
#include "kfiber_internal.h"
#include "kfiber_sync.h"
#include "katom.h"
#include "klog.h"
#include "kthread.h"
#include "kudp.h"

#ifndef _WIN32
#include <sys/mman.h>
#ifdef ANDROID
#ifndef ENABLE_LIBUCONTEXT
KBEGIN_DECLS
int getcontext(ucontext_t *ucp);
int setcontext(const ucontext_t *ucp);
void makecontext(ucontext_t *ucp, void (*func)(), int argc, ...);
int swapcontext(ucontext_t *oucp, const ucontext_t *ucp);
#endif
KEND_DECLS
#endif
#endif
#define ST_DEFAULT_STACK_SIZE (64*1024)
#ifdef LINUX
#ifndef NDEBUG
//#define KFIBER_PROTECTED
#endif 
#endif
#ifdef KFIBER_PROTECTED
#define KFIBER_REDZONE    4096
#else
#define KFIBER_REDZONE    0
#endif
#define KFIBER_WAIT_CODE(obj) obj

static volatile int32_t fiber_count = 0;

pthread_key_t kgl_main_fiber_key;
pthread_key_t kgl_current_fiber_key;
typedef struct _kfiber_chan_data kfiber_chan_data;
struct _kfiber_chan_data {
	void* data;
	int len;
	kfiber_chan_data* next;
};

struct _kfiber_chan {
	kfiber_chan_data* head;
	kfiber_chan_data* last;
	kfiber_waiter* reciver;
	kfiber_waiter* sender;
	volatile int buf_size;
	volatile int buf_limit;
	int closed;
};



#ifdef KF_ASYNC_WORKER
#define KFIBER_AIO_DEFAULT_WORKER 16
static kgl_list kfiber_aio_list;
static kasync_worker* kfiber_aio_worker = NULL;
#endif

static void kfiber_next_call(kfiber* fiber, result_callback cb, int got, bool same_thread)
{
	if (same_thread) {
		assert(fiber->selector == kgl_get_tls_selector());
		//assert(fiber->start_called == 1);
		fiber->cb = cb;
		fiber->arg = fiber;
		fiber->retval = got;
		kselector_add_fiber_ready(fiber->selector, fiber);
		return;
	}
	kgl_selector_module.next(fiber->selector, NULL, cb, fiber, got);
}
int kfiber_get_count()
{
	return (int)katom_get((void*)&fiber_count);
}
kfiber* kfiber_main()
{
	return (kfiber*)pthread_getspecific(kgl_main_fiber_key);
}
bool is_main_fiber(kfiber* fiber)
{
	if (fiber->switch_from == NULL) {
		assert(fiber == kfiber_main());
		return true;
	}
	assert(fiber != kfiber_main());
	return false;
}
bool kfiber_is_main()
{
	kfiber* fiber = kfiber_self();
	if (fiber == NULL || is_main_fiber(fiber)) {
		return true;
	}
	return false;
}

static void kfiber_delete_context(kfiber* fiber) {
	//printf("delete fiber=[%p]\n", fiber);
	assert(kfiber_self() == kfiber_main());
#ifdef _WIN32
	DeleteFiber(fiber->ctx);
#else
#ifdef KFIBER_PROTECTED
	if (mprotect(fiber->stack, KFIBER_REDZONE, PROT_READ | PROT_WRITE) != 0) {
		printf("begin mprotect stack=[%p]\n", fiber->stack);
		perror("mprotect");
	}
	int stk_size = (int)fiber->stk_page * _ST_PAGE_SIZE;
	if (mprotect((char*)(fiber->ctx.uc_stack.ss_sp) + stk_size, KFIBER_REDZONE, PROT_READ | PROT_WRITE) != 0) {
		printf("end address=[%p]\n", (char*)(fiber->ctx.uc_stack.ss_sp) + stk_size);
		perror("mprotect");
	}
#endif
	free(fiber->stack);
#endif
}
static void kfiber_destroy(kfiber* fiber)
{
	if (fiber->close_cond) {
		fiber->close_cond->f->release(fiber->close_cond);
	}
	assert(fiber->queue.next == NULL);
	xfree(fiber);
	katom_dec((void*)&fiber_count);
}
void kfiber_set_self(kfiber* thread)
{
	pthread_setspecific(kgl_current_fiber_key, thread);
}
kfiber* kfiber_self()
{
	return (kfiber*)pthread_getspecific(kgl_current_fiber_key);
}
void __kfiber_switch(kfiber* fiber_from, kfiber* fiber_to)
{
	//printf("switch fiber from [%p] to [%p]\n", fiber_from, fiber_to);
	assert(kfiber_self() == fiber_from);
	assert(fiber_from != fiber_to);
	kfiber_set_self(fiber_to);
#ifndef NDEBUG
	//kgl_get_stack_trace(fiber_to->sp);
#endif
#ifdef _WIN32
	assert(GetCurrentFiber() == fiber_from->ctx);
	SwitchToFiber(fiber_to->ctx);
#else
	//printf("swapcontext from=[%p %p] to=[%p %p]\n", fiber_from, fiber_from->start, fiber_to, fiber_to->start);

#ifndef DISABLE_KFIBER
	int swap_result = kfiber_swapcontext(&fiber_from->ctx, &fiber_to->ctx);
	if (swap_result!=0) {
		//printf("swapcontext error = [%d]\n",errno);
	}
#else
	fprintf(stderr, "DISABLE_KFIBER is on. swapcontext failed.");
#endif
#endif
	assert(kfiber_self() == fiber_from);
}

int __kfiber_wait(kfiber* fiber, void* obj)
{
	kassert(fiber->switch_from);
	kassert(fiber == kfiber_self());
#ifndef NDEBUG
	if (fiber->notice_flag) {
		assert(fiber->wait_code == KFIBER_WAIT_CODE(obj));
		if (KFIBER_WAIT_CODE(obj) != fiber->wait_code) {
			klog(KLOG_ERR, "BUG __kfiber_wait fiber=[%p] not expected,wakeup code=[%p], wait code=[%p]\n", fiber, KFIBER_WAIT_CODE(obj), fiber->wait_code);
			abort();
		}
	}
	else {
		fiber->wait_code = KFIBER_WAIT_CODE(obj);
	}
	fiber->wait_flag = 1;
#endif
	__kfiber_switch(fiber, fiber->switch_from);
	return fiber->retval;
}
int kfiber_wait(void* obj)
{
	kfiber* fiber = kfiber_self();
#ifndef NDEBUG
	fiber->wait_notice_flag = 0;
#endif
	return __kfiber_wait(fiber, obj);
}
void kfiber_wakeup(kfiber* fiber, void* obj, int ret)
{
	kfiber* fiber_from = kfiber_self();
	kassert(fiber_from);
	kassert(fiber_from->selector);
	kassert(fiber->selector);
	kassert(fiber_from->selector == fiber->selector);
#ifndef NDEBUG
	if (fiber->wait_flag) {
		kassert(KFIBER_WAIT_CODE(obj) == fiber->wait_code);
		if (KFIBER_WAIT_CODE(obj) != fiber->wait_code) {
			klog(KLOG_ERR, "BUG wakeup fiber=[%p] not expected,wakeup code=[%p], wait code=[%p]\n", fiber, KFIBER_WAIT_CODE(obj), fiber->wait_code);
			abort();
		}
	}
	else {
		fiber->wait_code = KFIBER_WAIT_CODE(obj);
	}
	fiber->notice_flag = 1;
#endif
	fiber->retval = ret;
	if (fiber_from == fiber) {
		return;
	}
	assert(fiber_from != fiber);
	fiber->switch_from = fiber_from;
	__kfiber_switch(fiber_from, fiber);
}

kev_result kfiber_thread_init(KOPAQUE data, void* arg, int got)
{
	if (got == 1) {
		//exit
		return kev_ok;
	}
	kfiber* fiber = kfiber_main();
	if (fiber != NULL) {
		fiber->selector = kgl_get_tls_selector();
		return kev_ok;
	}
	fiber = (kfiber*)xmemory_newz(sizeof(kfiber));
#ifdef _WIN32
	fiber->ctx = ConvertThreadToFiber(NULL);
	//printf("main ctx=[%p]\n", fiber->ctx);
#else

#endif
	fiber->selector = kgl_get_tls_selector();
	pthread_setspecific(kgl_main_fiber_key, fiber);
	kfiber_set_self(fiber);
	return kev_ok;
	//printf("main fiber=[%p]\n", fiber);
}
void kfiber_init()
{
	pthread_key_create(&kgl_main_fiber_key, NULL);
	pthread_key_create(&kgl_current_fiber_key, NULL);
#ifdef KF_ASYNC_WORKER
	klist_init(&kfiber_aio_list);
	kfiber_aio_worker = kasync_worker_init(KFIBER_AIO_DEFAULT_WORKER, 0);
#endif
	selector_manager_thread_init(kfiber_thread_init, NULL);
}
static void kfiber_release(kfiber* fiber)
{
	if (katom_dec((void*)&fiber->ref) == 0) {
		kfiber_destroy(fiber);
	}
}
static kev_result result_fiber_exit(KOPAQUE data, void* arg, int got)
{
	kfiber* fiber = (kfiber*)arg;
	fiber->retval = got;
	kfiber_delete_context(fiber);
	if (fiber->close_cond) {
		fiber->close_cond->f->notice(fiber->close_cond, got);
	}
	kfiber_release(fiber);
	return kev_ok;
}

static void kfiber_exit(kfiber* fiber, int retval)
{
#ifndef NDEBUG
	fiber->wait_notice_flag = 0;
#endif
	kfiber_next_call(fiber, result_fiber_exit, retval, true);
	__kfiber_wait(fiber, fiber->close_cond);
}
#ifdef _WIN32
void WINAPI fiber_start(void* arg) {
	kfiber* fiber = (kfiber*)arg;
	assert(kfiber_self()==fiber);
#else
void fiber_start() {
	kfiber *fiber = kfiber_self();
#endif
	int result = -1;
	while (!fiber->start_called) {
		fiber->start_called = 1;
		result = fiber->start(fiber->arg, fiber->retval);
	}
	kfiber_exit(fiber, result);
}
kev_result result_switch_fiber(KOPAQUE data, void* arg, int got)
{
	kfiber* fiber = (kfiber*)arg;
	kfiber_wakeup(fiber, data, got);
	return kev_fiber_ok;
}
#define result_fiber_accept result_switch_fiber
#if 0
kev_result result_fiber_accept(KOPAQUE data, void* arg, int got)
{
	kserver_selectable* ss = (kserver_selectable*)data;
	kfiber* fiber = (kfiber*)arg;
	kfiber_wakeup(fiber, data, got);
	return kev_fiber_ok;
}
#endif
void kfiber_wakeup2(kselector* selector, kfiber* fiber, void* obj, int retval)
{
	if (selector == kgl_get_tls_selector()) {
		kfiber_wakeup(fiber, obj, retval);
		return;
	}
	kgl_selector_module.next(selector, obj, result_switch_fiber, fiber, retval);
}

kfiber* kfiber_new(kfiber_start_func start, void* start_arg, int stk_size)
{
	kfiber* fiber;
	/* Adjust stack size */
	if (stk_size == 0) {
		stk_size = ST_DEFAULT_STACK_SIZE;
	}
	int stk_page = stk_size / _ST_PAGE_SIZE;
	stk_size = stk_page * _ST_PAGE_SIZE;

	fiber = (kfiber*)malloc(sizeof(kfiber));

	memset(fiber, 0, sizeof(kfiber));
	fiber->st_flags = STF_FIBER;
	fiber->ref = 1;
	fiber->start = start;
	fiber->arg = start_arg;
	fiber->stk_page = stk_page;
#ifdef _WIN32
	fiber->ctx = CreateFiber(stk_size, fiber_start, fiber);
#else
#ifndef DISABLE_KFIBER
	if (kfiber_getcontext(&fiber->ctx) == -1) {
		xfree(fiber);
		return NULL;
	}
	fiber->stack = kgl_memalign(4096, stk_size + 2 * KFIBER_REDZONE);
	fiber->ctx.uc_stack.ss_sp = (char*)fiber->stack + KFIBER_REDZONE;
	fiber->ctx.uc_stack.ss_size = stk_size;
	fiber->ctx.uc_link = NULL;
#ifdef KFIBER_PROTECTED
	if (mprotect(fiber->stack, KFIBER_REDZONE, PROT_NONE) != 0) {
		printf("begin mprotect stack=[%p]\n", fiber->stack);
		perror("mprotect");
	}
	if (mprotect((char*)(fiber->ctx.uc_stack.ss_sp) + stk_size, KFIBER_REDZONE, PROT_NONE) != 0) {
		printf("end address=[%p]\n", (char*)(fiber->ctx.uc_stack.ss_sp) + stk_size);
		perror("mprotect");
	}
#endif
	kfiber_makecontext(&fiber->ctx, (void(*)(void))fiber_start, 0);
#else
	fprintf(stderr, "DISABLE_KFIBER is set ON.");
#endif
#endif
	katom_inc((void*)&fiber_count);
	return fiber;
}
int kfiber_create_sync(kfiber_start_func start, void* arg, int len, int stk_size, kfiber** ret_fiber)
{
	kfiber* fiber = kfiber_new(start, arg, stk_size);
	if (fiber == NULL) {
		return -1;
	}
	fiber->selector = get_perfect_selector();
	if (ret_fiber) {
		fiber->ref++;
		*ret_fiber = fiber;
		fiber->close_cond = kfiber_cond_init_sync(false);
	}
	kfiber_wakeup2(fiber->selector, fiber, NULL, len);
	return 0;
}
int kfiber_create2(kselector* selector, kfiber_start_func start, void* arg, int len, int stk_size, kfiber** ret_fiber)
{
	kfiber* fiber = kfiber_new(start, arg, stk_size);
	if (fiber == NULL) {
		return -1;
	}
	fiber->selector = selector;
	if (ret_fiber) {
		fiber->ref++;
		*ret_fiber = fiber;
		fiber->close_cond = kfiber_cond_init_ts(false);
	}
	kfiber_wakeup2(selector, fiber, NULL, len);
	return 0;
}
int kfiber_start(kfiber* fiber, int len)
{
	fiber->selector = kgl_get_tls_selector();
	fiber->close_cond = kfiber_cond_init(false);
	fiber->ref++;
	kfiber_wakeup(fiber, NULL, len);
	return 0;
}
int kfiber_create(kfiber_start_func start, void* arg, int len, int stk_size, kfiber** ret_fiber)
{
	kfiber* fiber = kfiber_new(start, arg, stk_size);
	if (fiber == NULL) {
		return -1;
	}
	fiber->selector = kgl_get_tls_selector();
	if (ret_fiber) {
		fiber->ref++;
		*ret_fiber = fiber;
		fiber->close_cond = kfiber_cond_init(false);
	}
	kfiber_wakeup(fiber, NULL, len);
	return 0;
}

kev_result kfiber_join2(kfiber* fiber, KOPAQUE data, result_callback notice, void* arg)
{
	kassert(kfiber_is_main());
	if (fiber->close_cond == NULL) {
		kev_result result = notice(data, arg, -1);
		kfiber_release(fiber);
		return result;
	}
	kev_result result = fiber->close_cond->f->wait_callback(fiber->close_cond, data, notice, arg);
	kfiber_release(fiber);
	return result;
}

int kfiber_exit_callback(KOPAQUE data, result_callback notice, void* arg)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	if (fiber->close_cond == NULL) {
		fiber->close_cond = kfiber_cond_init(true);
	}
	return fiber->close_cond->f->wait_callback(fiber->close_cond, data, notice, arg);
}


bool kfiber_has_next()
{
	kfiber* fiber = kfiber_self();
	//CHECK_FIBER(fiber);
	return fiber->start_called == 0;
}

int kfiber_next(kfiber_start_func start, void* arg, int got)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	assert(fiber->start_called);
	fiber->start = start;
	fiber->arg = arg;
	fiber->retval = got;
	fiber->start_called = 0;
	return 0;
}

kfiber* kfiber_ref_self(bool thread_safe)
{
	kfiber* fiber = kfiber_self();
	assert(fiber && !is_main_fiber(fiber));
	if (fiber->close_cond == NULL) {
		if (thread_safe) {
			fiber->close_cond = kfiber_cond_init_ts(true);
		}
		else {
			fiber->close_cond = kfiber_cond_init(true);
		}
	}
	katom_inc((void*)&fiber->ref);
	return fiber;
}
int kfiber_join(kfiber* fiber, int* retval)
{
	assert(fiber->close_cond);
	if (fiber->close_cond == NULL) {
		kfiber_release(fiber);
		return -1;
	}
	if (fiber->close_cond->f->wait(fiber->close_cond) != 0) {
		kfiber_release(fiber);
		return -1;
	}
	if (retval) {
		*retval = fiber->retval;
	}
	kfiber_release(fiber);
	return 0;
}
int kfiber_msleep(int msec)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	kselector_add_timer(kgl_get_tls_selector(), result_switch_fiber, fiber, msec, NULL);
	__kfiber_wait(fiber, NULL);
	return 0;
}

static kev_result kfiber_getaddr_callback(void* arg, kgl_addr* addr)
{
	kfiber* fiber = (kfiber*)arg;
	if (addr) {
		kgl_addr_refs(addr);
		kgl_addr** ret = (kgl_addr**)fiber->arg;
		*ret = addr;
	}
	kfiber_wakeup(fiber, (void*)kfiber_getaddr_callback, addr ? 0 : -1);
	return kev_fiber_ok;
}
static int kfiber_buffer_callback(KOPAQUE data, void* arg, WSABUF* buf, int bc)
{
	kfiber* fiber = (kfiber*)arg;
	int copy_bc = MIN(bc, fiber->retval);
	kgl_memcpy(buf, fiber->arg, copy_bc * sizeof(WSABUF));
	return copy_bc;
}
int kfiber_net_listen(kserver* server, int flag, kserver_selectable** ss)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	*ss = kserver_listen(server, flag, result_fiber_accept);
	return 0;
}
int kfiber_net_accept(kserver_selectable* ss, kconnection** c)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	assert(ss->st.selector == kgl_get_tls_selector());
	fiber->retval = -1;
	if (ss->server->closed || !kserver_selectable_accept(ss, fiber)) {
		return -1;
	}
	assert(ss->st.data == ss);
	//printf("accept filber=[%p] ss=[%p]\n", fiber, ss);
	__kfiber_wait(fiber, (void*)ss->st.data);
	*c = accept_result_new_connection(ss, fiber->retval);
	if (*c) {
		(*c)->st.selector = ss->st.selector;
	}
	return 0;
}
int kfiber_net_getaddr(const char* hostname, kgl_addr** addr)
{
	struct addrinfo* res = NULL;
	struct addrinfo f;
	memset(&f, 0, sizeof(f));
	f.ai_family = PF_UNSPEC;
	f.ai_flags = AI_NUMERICHOST;
#ifndef KSOCKET_IPV6
	f.ai_family = PF_INET;
#endif
	getaddrinfo(hostname, NULL, &f, &res);
	if (res != NULL) {
		*addr = kgl_addr_new(res);
		return 0;
	}
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	fiber->retval = -1;
	fiber->arg = addr;
	if (kev_fiber_ok != kgl_find_addr(hostname, kgl_addr_ip, kfiber_getaddr_callback, fiber, kgl_get_tls_selector())) {
		__kfiber_wait(fiber, (void*)kfiber_getaddr_callback);
	}
	return fiber->retval;
}

int kfiber_net_connect(kconnection* c, sockaddr_i* bind_addr, int tproxy_mask)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	if (!kconnection_half_connect(c, bind_addr, tproxy_mask)) {
		return -1;
	}
	selectable_bind(&c->st, kgl_get_tls_selector());
	if (kev_fiber_ok != kconnection_connect(c, result_switch_fiber, fiber)) {
		__kfiber_wait(fiber, c->st.data);
	}
	return fiber->retval;
}
int kfiber_net_write(kconnection* cn, const char* buf, int len)
{
	WSABUF v;
	v.iov_base = (char*)buf;
	v.iov_len = len;
	return kfiber_net_writev(cn, &v, 1);
}

int kfiber_net_writev(kconnection* cn, WSABUF* buf, int vc)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	fiber->retval = vc;
	fiber->arg = buf;
	if (kev_fiber_ok != selectable_write(&cn->st, result_switch_fiber, kfiber_buffer_callback, fiber)) {
		__kfiber_wait(fiber, cn->st.data);
	}
	return fiber->retval;
}
int kfiber_udp_readv(kconnection* cn, WSABUF* buf, int vc)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	fiber->retval = vc;
	fiber->arg = buf;
	if (kev_fiber_ok != kudp_recv_from(cn, result_switch_fiber, kfiber_buffer_callback, fiber)) {
		__kfiber_wait(fiber, cn->st.data);
	}
	return fiber->retval;
}
int kfiber_udp_read(kconnection* cn, char* buf, int len)
{
	WSABUF v;
	v.iov_base = buf;
	v.iov_len = len;
	return kfiber_udp_readv(cn, &v, 1);
}
int kfiber_net_readv(kconnection* cn, WSABUF* buf, int vc)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	fiber->retval = vc;
	fiber->arg = buf;
	if (kev_fiber_ok != selectable_read(&cn->st, result_switch_fiber, kfiber_buffer_callback, fiber)) {
		__kfiber_wait(fiber, cn->st.data);
	}
	return fiber->retval;
}
int kfiber_net_read(kconnection* cn, char* buf, int len)
{
	WSABUF v;
	v.iov_base = buf;
	v.iov_len = len;
	return kfiber_net_readv(cn, &v, 1);
}
#ifdef KSOCKET_SSL
kev_result result_fiber_ssl_shutdown(KOPAQUE data, void* arg, int got)
{
	kfiber* fiber = (kfiber*)arg;
	switch (got) {
	case -1:
		kfiber_wakeup(fiber, data, -1);
		return kev_fiber_ok;
	case 1:
		kfiber_wakeup(fiber, data, 0);
		return kev_fiber_ok;
	default:
		return kselectable_ssl_shutdown((kselectable*)fiber->arg, result_fiber_ssl_shutdown, fiber);
	}
}
kev_result result_fiber_ssl_handshake(KOPAQUE data, void* arg, int got)
{
	//printf("result_fiber_ssl_handshake=[%d]\n", got);
	kfiber* fiber = (kfiber*)arg;
	switch (got) {
	case -1:
		kfiber_wakeup(fiber, data, -1);
		return kev_fiber_ok;
	case 1:
		kfiber_wakeup(fiber, data, 0);
		return kev_fiber_ok;
	default:
		return kselectable_ssl_handshake((kselectable*)fiber->arg, result_fiber_ssl_handshake, fiber);
	}
}
int kfiber_ssl_handshake(kconnection* cn)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	cn->st.ssl->handshake = 1;
	//KBIT_SET(cn->st.st_flags, STF_SSL_HANDSHAKE);
	fiber->arg = &cn->st;
	if (kselectable_ssl_handshake(&cn->st, result_fiber_ssl_handshake, fiber) != kev_fiber_ok) {
		__kfiber_wait(fiber, cn->st.data);
	}
	return fiber->retval;
}
int kfiber_ssl_shutdown(kconnection *c)
{
	if (kconnection_is_ssl_handshake(c) && !c->st.ssl->shutdown) {
		kfiber* fiber = kfiber_self();
		CHECK_FIBER(fiber);
		c->st.data = NULL;
		if (!KBIT_TEST(c->st.st_flags, STF_ERR)) {
			fiber->arg = &c->st;
			if (kev_fiber_ok != kselectable_ssl_shutdown((kselectable*)fiber->arg, result_fiber_ssl_shutdown, fiber)) {
				__kfiber_wait(fiber, NULL);
			}
		}
		c->st.ssl->shutdown = 1;
	}
	return 0;
}
#endif
int kfiber_net_shutdown(kconnection *c)
{
#ifdef KSOCKET_SSL
	kfiber_ssl_shutdown(c);
#endif
	return ksocket_shutdown(c->st.fd, SHUT_RDWR);
}
int kfiber_net_close(kconnection* c)
{
#ifdef KSOCKET_SSL
	kfiber_ssl_shutdown(c);
#endif
	kconnection_real_destroy(c);
	return 0;
}
kfiber_file* kfiber_file_bind(FILE_HANDLE fp,int kf_flags)
{
	kselector* selector = kgl_get_tls_selector();
	if (selector == NULL) {
		return NULL;
	}
	kfiber_file* af = (kfiber_file*)xmemory_newz(sizeof(kfiber_file));
	kgl_selector_module.aio_open(selector, &af->fp, fp);
#ifdef KF_ASYNC_WORKER
	if (!KBIT_TEST(kf_flags, KFILE_ASYNC)) {
		KBIT_SET(af->fp.flags, KF_ASYNC_WORKER);
	}
#endif
	return af;
}
kfiber_file* kfiber_file_open(const char* filename, fileModel model, int kf_flags)
{

#ifndef KF_ASYNC_WORKER
	kf_flags |= KFILE_ASYNC;
#endif
#ifdef DARWIN
	kf_flags &= ~KFILE_ASYNC;
#endif
	FILE_HANDLE fp = kfopen(filename, model, kf_flags);
	if (!kflike(fp)) {
		return NULL;
	}
	kfiber_file* af = kfiber_file_bind(fp, kf_flags);
	if (af == NULL) {
		kfclose(fp);
		return NULL;
	}
	return af;
}
#ifdef KF_ASYNC_WORKER
static kev_result kfiber_aio_callback(void* data, int msec)
{
	kfiber* fiber = (kfiber*)data;
	kfiber_file* file = (kfiber_file*)fiber->arg;
	int ret;
	switch (file->fp.kiocb.cmd) {
	case kf_aio_read:
		ret = (int)pread(file->fp.fd, file->fp.buf, (size_t)file->fp.length, file->offset);
		break;
	case kf_aio_write:
		ret = (int)pwrite(file->fp.fd, file->fp.buf, (size_t)file->fp.length, file->offset);
		break;
	default:
		ret = -1;
		break;
	}
	if (ret > 0) {
		file->offset += ret;
	}
	kgl_selector_module.next(fiber->selector, kasync_file_get_opaque(&file->fp), result_switch_fiber, fiber, ret);
	return kev_fiber_ok;
}
#endif
static kev_result kfiber_file_callback(kasync_file* fp, void* arg, char* buf, int length)
{
	kfiber_file* file = (kfiber_file*)fp;
	//printf("kfiber_file_callback fiber=[%p] offset=[%d],got=[%d]\n", arg, (int)file->offset,length);
	if (length > 0) {
		file->offset += length;
	}
	kfiber_wakeup((kfiber*)arg, kasync_file_get_opaque(fp), length);
	return kev_fiber_ok;
}
int64_t kfiber_file_size(kfiber_file* fp)
{
	return kfsize(kasync_file_get_handle(&fp->fp));
}
int kfiber_file_read(kfiber_file* file, char* buf, int length)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	kasync_file_bind_opaque(&file->fp, &fiber);
#ifdef KF_ASYNC_WORKER
	if (KBIT_TEST(file->fp.flags, KF_ASYNC_WORKER)) {
		file->fp.length = length;
		file->fp.buf = buf;
		file->fp.kiocb.cmd = kf_aio_read;
		fiber->arg = file;
		assert(kfiber_aio_worker);
		kasync_worker_start(kfiber_aio_worker, fiber, kfiber_aio_callback);
		__kfiber_wait(fiber, &fiber);
		return fiber->retval;
	}
#endif
	//printf("kfiber=[%p] read offset=[%d]\n", fiber, (int)file->offset);

	kselector* selector = kasync_file_get_selector(&file->fp);
	if (!kgl_selector_module.aio_read(selector, &file->fp, buf, file->offset, length, kfiber_file_callback, fiber)) {
		return -1;
	}
	__kfiber_wait(fiber, &fiber);
	return fiber->retval;
}
int kfiber_file_write(kfiber_file* file, const char* buf, int length)
{
	kfiber* fiber = kfiber_self();
	kasync_file_bind_opaque(&file->fp, &fiber);
	CHECK_FIBER(fiber);
#ifdef KF_ASYNC_WORKER
	if (KBIT_TEST(file->fp.flags, KF_ASYNC_WORKER)) {
		file->fp.length = length;
		file->fp.buf = (char*)buf;
		file->fp.kiocb.cmd = kf_aio_write;
		fiber->arg = file;
		assert(kfiber_aio_worker);
		kasync_worker_start(kfiber_aio_worker, fiber, kfiber_aio_callback);
		__kfiber_wait(fiber, &fiber);
		return fiber->retval;
	}
#endif
	//printf("kfiber=[%p] write offset=[%d]\n", fiber, (int)file->offset);
	kselector* selector = kasync_file_get_selector(&file->fp);
	if (!kgl_selector_module.aio_write(selector, &file->fp, (char*)buf, file->offset, length, kfiber_file_callback, fiber)) {
		return -1;
	}
	__kfiber_wait(fiber, &fiber);
	//printf("kfiber=[%p] write wakeup retval=[%d]\n", kfiber_self(), fiber->retval);
	//print_stack_trace(fiber->sp);
	return fiber->retval;
}
int kfiber_file_seek(kfiber_file* file, seekPosion pos, int64_t offset)
{
	switch (pos) {
	case seekBegin:
		file->offset = offset;
		return 0;
	case seekCur:
		file->offset += offset;
		return 0;
	default:
		return -1;
	}
}
int64_t kfiber_file_tell(kfiber_file* file)
{
	return file->offset;
}
void kfiber_file_close(kfiber_file* file)
{
	kasync_file_close(&file->fp);
	xfree(file);
}

bool kfiber_check_result_callback(result_callback cb)
{
	if (kfiber_self() == kfiber_main()) {
		return true;
	}
	if (cb == result_switch_fiber) {
		return true;
	}
	if (cb == result_fiber_exit) {
		return true;
	}
#ifdef KSOCKET_SSL
	if (cb == result_fiber_ssl_handshake || cb == result_fiber_ssl_shutdown) {
		return true;
	}
#endif
	return false;
}
bool kfiber_check_file_callback(aio_callback cb)
{
	if (kfiber_self() == kfiber_main()) {
		return true;
	}
	if (cb == kfiber_file_callback) {
		return true;
	}
	return false;
}
bool kfiber_check_addr_callback(kgl_addr_call_back cb)
{
	if (kfiber_self() == kfiber_main()) {
		return true;
	}
	if (cb == kfiber_getaddr_callback) {
		return true;
	}
	return false;
}
//chan
kfiber_chan* kfiber_chan_create(int buf_size)
{
	assert(buf_size >= 0);
	kfiber_chan* ch = (kfiber_chan*)xmemory_newz(sizeof(kfiber_chan));
	ch->buf_limit = buf_size;
	return ch;
}
int kfiber_chan_send(kfiber_chan* ch, void* data, int len)
{
	kfiber* fiber = kfiber_self();
	assert(fiber);
	CHECK_FIBER(fiber);
	if (ch->closed) {
		return -1;
	}
	kfiber_chan_data* ch_data = xmemory_new(kfiber_chan_data);
	ch_data->data = data;
	ch_data->len = len;
	ch_data->next = NULL;
	ch->buf_size += len;
	if (ch->last) {
		ch->last->next = ch_data;
	}
	else {
		ch->head = ch_data;
	}
	ch->last = ch_data;
	if (ch->reciver) {
		//waitup all receiver
		kfiber_waiter* waiter = ch->reciver;
		ch->reciver = NULL;
		while (waiter) {
			kfiber_waiter* next = waiter->next;
			kfiber_wakeup_waiter(waiter, 0);
			xfree(waiter);
			waiter = next;
		}
	}
	while (ch->buf_size > ch->buf_limit) {
		kfiber_add_waiter(&ch->sender, kgl_get_tls_selector(), &fiber, result_switch_fiber, fiber);
		__kfiber_wait(fiber, &fiber);
	}
	return 0;
}
int kfiber_chan_recv(kfiber_chan* ch, void** data)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	for (;;) {
		if (ch->head) {
			*data = ch->head->data;
			int len = ch->head->len;
			ch->head = ch->head->next;
			if (ch->head == NULL) {
				ch->last = NULL;
			}
			ch->buf_size -= len;
			if (ch->sender && ch->buf_size <= ch->buf_limit) {
				kfiber_waiter* waiter = ch->sender;
				ch->sender = NULL;
				while (waiter) {
					kfiber_waiter* next = waiter->next;
					kfiber_wakeup_waiter(waiter, 0);
					xfree(waiter);
					waiter = next;
				}
			}
			return len;
		}
		if (ch->closed) {
			*data = NULL;
			return 0;
		}
		kfiber_add_waiter(&ch->reciver, kgl_get_tls_selector(), &fiber, result_switch_fiber, fiber);
		__kfiber_wait(fiber, &fiber);
	}
}
int kfiber_chan_shutdown(kfiber_chan* ch)
{
	ch->closed = 1;
	return 0;
}
int kfiber_chan_close(kfiber_chan* ch)
{
	assert(ch->reciver == NULL && ch->sender == NULL);
	assert(ch->head == NULL && ch->last == NULL);
	assert(ch->buf_size == 0);
	xfree(ch);
	return 0;
}
KTHREAD_FUNCTION _kfiber_worker_thread(void* arg)
{
	kfiber* fiber = (kfiber*)arg;
	int result = fiber->start(fiber->arg, fiber->retval);
	kfiber_wakeup2(fiber->selector, fiber, fiber->arg, result);
	KTHREAD_RETURN;
}
int kfiber_thread_call(kfiber_start_func start, void* arg, int argc, int* ret)
{
	kfiber* fiber = kfiber_self();
	CHECK_FIBER(fiber);
	fiber->start = start;
	fiber->arg = arg;
	fiber->retval = argc;
	if (!kthread_pool_start(_kfiber_worker_thread, fiber)) {
		return -1;
	}
	if (ret == NULL) {
		__kfiber_wait(fiber, arg);
		return 0;
	}
	*ret = __kfiber_wait(fiber, arg);
	return 0;
}

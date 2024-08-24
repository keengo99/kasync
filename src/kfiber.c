#include "kfeature.h"
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
int getcontext(ucontext_t* ucp);
int setcontext(const ucontext_t* ucp);
void makecontext(ucontext_t* ucp, void (*func)(), int argc, ...);
int swapcontext(ucontext_t* oucp, const ucontext_t* ucp);
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

static INLINE void kfiber_next_call(kfiber* fiber, result_callback cb, int got, bool same_thread) {
	if (same_thread) {
		assert(fiber->base.selector == kgl_get_tls_selector());
		//assert(fiber->start_called == 1);
		fiber->cb = cb;
		fiber->arg = fiber;
		fiber->retval = got;
		kselector_add_fiber_ready(fiber->base.selector, fiber);
		return;
	}
	kgl_selector_module.next(fiber->base.selector, NULL, cb, fiber, got);
}
int kfiber_get_count() {
	return (int)katom_get((void*)&fiber_count);
}
kfiber* kfiber_main() {
	return (kfiber*)pthread_getspecific(kgl_main_fiber_key);
}
bool is_main_fiber(kfiber* fiber) {
	if (fiber->switch_from == NULL) {
		assert(fiber == kfiber_main());
		return true;
	}
	assert(fiber != kfiber_main());
	return false;
}
bool kfiber_is_main() {
	kselector* selector = kgl_get_tls_selector();
	return selector == NULL || is_main_fiber(kselector_get_fiber(selector));
}

static INLINE void kfiber_delete_context(kfiber* fiber) {
	assert(kfiber_self2() == kfiber_main());
#ifdef ENABLE_WIN_FIBER
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
#endif
}
static INLINE void kfiber_destroy(kfiber* fiber) {
	if (fiber->close_cond) {
		fiber->close_cond->f->release(fiber->close_cond);
	}
	assert(fiber->base.queue.next == NULL);
	xfree(fiber);
	katom_dec((void*)&fiber_count);
}
INLINE void kfiber_set_self(kfiber* fiber) {
	kselector_set_fiber(fiber->base.selector, fiber);
}
#ifdef ENABLE_FCONTEXT
static INLINE void update_fcontext(transfer_t rt) {
	((kfiber*)rt.data)->ctx = rt.fctx;
}
#endif
void __kfiber_switch(kfiber* fiber_from, kfiber* fiber_to) {
	assert(kfiber_self2() == fiber_from);
	assert(fiber_from != fiber_to);
	kfiber_set_self(fiber_to);
#ifndef NDEBUG
	//kgl_get_stack_trace(fiber_to->sp);
#endif
#ifdef ENABLE_FCONTEXT
	update_fcontext(jump_fcontext(fiber_to->ctx, fiber_from));
#else
#ifdef _WIN32
	assert(GetCurrentFiber() == fiber_from->ctx);
	SwitchToFiber(fiber_to->ctx);
#else
	//printf("swapcontext from=[%p %p] to=[%p %p]\n", fiber_from, fiber_from->start, fiber_to, fiber_to->start);

#ifndef DISABLE_KFIBER
	int swap_result = kfiber_swapcontext(&fiber_from->ctx, &fiber_to->ctx);
	if (swap_result != 0) {
		//printf("swapcontext error = [%d]\n",errno);
	}
#else
	fprintf(stderr, "DISABLE_KFIBER is on. swapcontext failed.");
#endif
#endif
#endif
	assert(kfiber_self2() == fiber_from);
}

static INLINE void kfiber_release(kfiber* fiber) {
	if (katom_dec((void*)&fiber->base.ref) == 0) {
		kfiber_destroy(fiber);
	}
}
static kev_result result_fiber_exit(KOPAQUE data, void* arg, int got) {
	kfiber* fiber = (kfiber*)arg;
	fiber->retval = got;
	kfiber_delete_context(fiber);
	if (fiber->close_cond) {
		fiber->close_cond->f->notice(fiber->close_cond, got);
	}
	kfiber_release(fiber);
	return kev_ok;
}

static INLINE void kfiber_exit(kfiber* fiber, int retval) {
#ifndef NDEBUG
	fiber->wait_notice_flag = 0;
#endif
	kfiber_next_call(fiber, result_fiber_exit, retval, true);
	__kfiber_wait(fiber, fiber->close_cond);
}
#ifdef ENABLE_FCONTEXT
static void fiber_start(transfer_t rt) {
	update_fcontext(rt);
	kfiber* fiber = kfiber_self(&((kfiber*)rt.data)->base);
#else
#ifdef _WIN32
static void WINAPI fiber_start(void* arg) {
	kfiber* fiber = (kfiber*)arg;
	assert(kfiber_self2() == fiber);
#else
static void fiber_start() {
	kfiber* fiber = kfiber_self2();
#endif
#endif
#ifndef NDEBUG
	fiber->wait_notice_flag = 0;
#endif
	kfiber_exit(fiber, fiber->start(fiber->arg, fiber->retval));
}
kev_result kfiber_thread_init(KOPAQUE data, void* arg, int got) {
	if (got == 1) {
		//exit
		return kev_ok;
	}
	kfiber* fiber = kfiber_main();
	if (fiber != NULL) {
		fiber->base.selector = kgl_get_tls_selector();
		return kev_ok;
	}
	fiber = (kfiber*)xmemory_newz(sizeof(kfiber));
#ifdef ENABLE_WIN_FIBER
	fiber->ctx = ConvertThreadToFiber(NULL);
#endif
	fiber->base.selector = kgl_get_tls_selector();
	pthread_setspecific(kgl_main_fiber_key, fiber);
	kfiber_set_self(fiber);
	return kev_ok;
	//printf("main fiber=[%p]\n", fiber);
}
void kfiber_init() {
	pthread_key_create(&kgl_main_fiber_key, NULL);
	selector_manager_thread_init(kfiber_thread_init, NULL);
}
kev_result kfiber_result_callback(KOPAQUE data, void* arg, int got) {
	kfiber* fiber = (kfiber*)arg;
	kfiber_wakeup(fiber, data, got);
	return kev_fiber_ok;
}
#define result_fiber_accept kfiber_result_callback

void kfiber_wakeup2(kselector * selector, kfiber * fiber, void* obj, int retval) {
	if (selector == kgl_get_tls_selector()) {
		kfiber_wakeup(fiber, obj, retval);
		return;
	}
	kgl_selector_module.next(selector, obj, kfiber_result_callback, fiber, retval);
}
const char* kfiber_powered_by() {
#ifdef ENABLE_FCONTEXT
	return "fcontext";
#elif defined(ENABLE_WIN_FIBER)
	return "winfiber";
#elif defined(ENABLE_LIBUCONTEXT)
	return "libucontext";
#elif defined(DISABLE_KFIBER)
	return "none";
#else
	return "ucontext";
#endif
}
kfiber* kfiber_new(kfiber_start_func start, void* start_arg, int stk_size) {
	kfiber* fiber;
	int stk_page = stk_size / _ST_PAGE_SIZE;
	stk_size = stk_page * _ST_PAGE_SIZE;
	if (stk_size == 0) {
		stk_size = ST_DEFAULT_STACK_SIZE;
	}
#ifndef NDEBUG
#ifndef ENABLE_WIN_FIBER
	stk_size += ST_DEFAULT_STACK_SIZE;
#endif
#endif
#ifdef ENABLE_WIN_FIBER
	fiber = (kfiber*)malloc(sizeof(kfiber));
#else
	fiber = (kfiber*)malloc(sizeof(kfiber) + stk_size + 2 * KFIBER_REDZONE);
#endif
	//printf("new fiber [%p] stk_size=[%d]\n", fiber, stk_size);
	memset(fiber, 0, sizeof(kfiber));
	fiber->base.st_flags = STF_FIBER;
	fiber->base.ref = 1;
	fiber->start = start;
	fiber->arg = start_arg;
#ifdef ENABLE_FCONTEXT
	fiber->ctx = make_fcontext((char*)(fiber + 1) + KFIBER_REDZONE + stk_size, stk_size, fiber_start);
#elif defined(ENABLE_WIN_FIBER)
	fiber->ctx = CreateFiber(stk_size, fiber_start, fiber);
#else
#ifndef DISABLE_KFIBER
	if (kfiber_getcontext(&fiber->ctx) == -1) {
		xfree(fiber);
		return NULL;
	}
	fiber->ctx.uc_stack.ss_sp = (char*)(fiber + 1) + KFIBER_REDZONE;
	fiber->ctx.uc_stack.ss_size = stk_size;
	fiber->ctx.uc_link = NULL;
	kfiber_makecontext(&fiber->ctx, (void(*)(void))fiber_start, 0);
#else
	fprintf(stderr, "DISABLE_KFIBER is set ON.");
#endif
#endif
	katom_inc((void*)&fiber_count);
	return fiber;
}
int kfiber_create_sync(kfiber_start_func start, void* arg, int len, int stk_size, kfiber * *ret_fiber) {
	kfiber* fiber = kfiber_new(start, arg, stk_size);
	if (fiber == NULL) {
		return -1;
	}
	fiber->base.selector = get_perfect_selector();
	if (ret_fiber) {
		fiber->base.ref++;
		*ret_fiber = fiber;
		fiber->close_cond = kfiber_cond_init_sync(false);
	}
	kfiber_wakeup2(fiber->base.selector, fiber, NULL, len);
	return 0;
}
int kfiber_create2(kselector * selector, kfiber_start_func start, void* arg, int len, int stk_size, kfiber * *ret_fiber) {
	kfiber* fiber = kfiber_new(start, arg, stk_size);
	if (fiber == NULL) {
		return -1;
	}
	if (selector == NULL) {
		fiber->base.selector = kgl_get_tls_selector();
		if (ret_fiber) {
			fiber->base.ref++;
			*ret_fiber = fiber;
			fiber->close_cond = kfiber_cond_init(false);
		}
		kfiber_wakeup(fiber, NULL, len);
		return 0;
	}
	fiber->base.selector = selector;
	if (ret_fiber) {
		fiber->base.ref++;
		*ret_fiber = fiber;
		fiber->close_cond = kfiber_cond_init_ts(false);
	}
	kfiber_wakeup2(selector, fiber, NULL, len);
	return 0;
}
int kfiber_start(kfiber * fiber, int len) {
	fiber->base.selector = kgl_get_tls_selector();
	fiber->close_cond = kfiber_cond_init(false);
	fiber->base.ref++;
	kfiber_wakeup(fiber, NULL, len);
	return 0;
}
kev_result kfiber_join2(kfiber * fiber, KOPAQUE data, result_callback notice, void* arg) {
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

int kfiber_exit_callback(KOPAQUE data, result_callback notice, void* arg) {
	kfiber* fiber = kfiber_self2();
	CHECK_FIBER(fiber);
	if (fiber->close_cond == NULL) {
		fiber->close_cond = kfiber_cond_init(true);
	}
	return fiber->close_cond->f->wait_callback(fiber->close_cond, data, notice, arg);
}
kfiber* kfiber_ref_self(bool thread_safe) {
	kfiber* fiber = kfiber_self2();
	assert(fiber && !is_main_fiber(fiber));
	if (fiber->close_cond == NULL) {
		if (thread_safe) {
			fiber->close_cond = kfiber_cond_init_ts(true);
		} else {
			fiber->close_cond = kfiber_cond_init(true);
		}
	}
	katom_inc((void*)&fiber->base.ref);
	return fiber;
}
int kfiber_try_join(kfiber * fiber, int* retval) {
	assert(fiber->close_cond);
	if (fiber->close_cond == NULL) {
		return -1;
	}
	if (fiber->close_cond->f->try_wait(fiber->close_cond, retval) != 0) {
		return -1;
	}
	if (retval) {
		*retval = fiber->retval;
	}
	kfiber_release(fiber);
	return 0;
}
int kfiber_join(kfiber * fiber, int* retval) {
	assert(fiber->close_cond);
	if (fiber->close_cond == NULL) {
		kfiber_release(fiber);
		return 0;
	}
	if (fiber->close_cond->f->wait(fiber->close_cond, retval) != 0) {
		kfiber_release(fiber);
		return 0;
	}
	if (retval) {
		*retval = fiber->retval;
	}
	kfiber_release(fiber);
	return 0;
}
int kfiber_msleep(int msec) {
	kfiber* fiber = kfiber_self2();
	CHECK_FIBER(fiber);
	int result = kselector_add_timer(kgl_get_tls_selector(), kfiber_result_callback, fiber, msec, NULL);
	if (result != 0) {
		return result;
	}
	__kfiber_wait(fiber, NULL);
	return 0;
}

static kev_result kfiber_getaddr_callback(void* arg, kgl_addr * addr) {
	kfiber* fiber = (kfiber*)arg;
	if (addr) {
		kgl_addr_refs(addr);
		kgl_addr** ret = (kgl_addr**)fiber->arg;
		*ret = addr;
	}
	kfiber_wakeup(fiber, (void*)kfiber_getaddr_callback, addr ? 0 : -1);
	return kev_fiber_ok;
}
int kfiber_net_listen(kserver * server, int flag, kserver_selectable * *ss) {
	kfiber* fiber = kfiber_self2();
	CHECK_FIBER(fiber);
	*ss = kserver_listen(server, flag, result_fiber_accept);
	if (*ss) {
		KBIT_SET(server->flags, KGL_SERVER_START);
	}
	return 0;
}
int kfiber_net_accept(kserver_selectable * ss, kconnection * *c) {
	kfiber* fiber = kfiber_self(&ss->st.base);
	CHECK_FIBER(fiber);
	assert(ss->st.base.selector == kgl_get_tls_selector());
	fiber->retval = -1;
	if (!kserver_selectable_accept(ss, fiber)) {
		return -1;
	}
	assert(ss->st.data == ss);
	//printf("accept filber=[%p] ss=[%p]\n", fiber, ss);
	__kfiber_wait(fiber, (void*)ss->st.data);
	*c = accept_result_new_connection(ss, fiber->retval);
	if (*c) {
		selectable_bind(&(*c)->st, ss->st.base.selector);
	}
	return 0;
}
int kfiber_net_getaddr(const char* hostname, kgl_addr * *addr) {
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
	kfiber* fiber = kfiber_self2();
	CHECK_FIBER(fiber);
	fiber->retval = -1;
	fiber->arg = addr;
	return kfiber_wait_result(fiber, kgl_find_addr(hostname, kgl_addr_ip, kfiber_getaddr_callback, fiber, kgl_get_tls_selector()), (void*)kfiber_getaddr_callback);
}

int kfiber_net_connect(kconnection * c, sockaddr_i * bind_addr, int tproxy_mask) {
	kselector* selector = kgl_get_tls_selector();
	kfiber* fiber = kselector_get_fiber(selector);
	CHECK_FIBER(fiber);
	if (!kconnection_half_connect(c, bind_addr, tproxy_mask)) {
		return -1;
	}
	selectable_bind(&c->st, selector);
	return kfiber_wait_result(fiber, kconnection_connect(c, kfiber_result_callback, fiber), c->st.data);
}
static kev_result kfiber_result_sendfile(KOPAQUE data, void* arg, int got) {
	kasync_file* file = (kasync_file*)arg;
	if (got > 0) {
		file->st.offset += got;
	}
	kfiber_wakeup((kfiber*)kasync_file_get_opaque(file), arg, got);
	return kev_fiber_ok;
}
int kfiber_sendfile(kconnection * cn, kfiber_file * file, int length) {
	kfiber* fiber = kfiber_self(&cn->st.base);
	CHECK_FIBER(fiber);
	kasync_file_bind_opaque(file, fiber);
	kgl_iovec buf;
	buf.iov_base = (char*)file;
	buf.iov_len = length;
	return kfiber_wait_result(fiber, selectable_sendfile(&cn->st, kfiber_result_sendfile, &buf, file), file);
}
#ifdef KSOCKET_SSL
kev_result result_fiber_ssl_shutdown(KOPAQUE data, void* arg, int got) {
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
kev_result result_fiber_ssl_handshake(KOPAQUE data, void* arg, int got) {
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
int kfiber_ssl_handshake(kconnection * cn) {
	kfiber* fiber = kfiber_self(&cn->st.base);
	CHECK_FIBER(fiber);
	cn->st.ssl->handshake = 1;
	//KBIT_SET(cn->st.base.st_flags, STF_SSL_HANDSHAKE);
	fiber->arg = &cn->st;
	return kfiber_wait_result(fiber, kselectable_ssl_handshake(&cn->st, result_fiber_ssl_handshake, fiber), cn->st.data);
}
int kfiber_ssl_shutdown(kconnection * c) {
	if (kconnection_is_ssl_handshake(c) && !c->st.ssl->shutdown) {
		if (c->st.base.selector != NULL) {
			kfiber* fiber = kfiber_self(&c->st.base);
			CHECK_FIBER(fiber);
			c->st.data = NULL;
			if (!KBIT_TEST(c->st.base.st_flags, STF_ERR)) {
				fiber->arg = &c->st;
				kfiber_wait_result(fiber, kselectable_ssl_shutdown((kselectable*)fiber->arg, result_fiber_ssl_shutdown, fiber), NULL);
			}
		}
		c->st.ssl->shutdown = 1;
	}
	return 0;
}
#endif
int kfiber_net_shutdown(kconnection * c) {
#ifdef KSOCKET_SSL
	kfiber_ssl_shutdown(c);
#endif
	return ksocket_shutdown(c->st.fd, SHUT_RDWR);
}
int kfiber_net_close(kconnection * c) {
#ifdef KSOCKET_SSL
	kfiber_ssl_shutdown(c);
#endif
	kconnection_real_destroy(c);
	return 0;
}
kfiber_file* kfiber_file_bind(FILE_HANDLE fp) {
	kselector* selector = kgl_get_tls_selector();
	if (selector == NULL) {
		return NULL;
	}
	kfiber_file* af = (kfiber_file*)xmemory_newz(sizeof(kfiber_file));
	kgl_selector_module.aio_open(selector, af, fp);
	KBIT_SET(af->st.base.st_flags, STF_AIO_FILE);
	return af;
}
kfiber_file* kfiber_file_open(const char* filename, fileModel model, int kf_flags) {
	KBIT_SET(kf_flags, KFILE_ASYNC);
	FILE_HANDLE fp = kfopen(filename, model, kf_flags);
	if (!kflike(fp)) {
		return NULL;
	}
	kfiber_file* af = kfiber_file_bind(fp);
	if (af == NULL) {
		kfclose(fp);
		return NULL;
	}
	return af;
}
static kev_result kfiber_file_callback(KOPAQUE data, void* arg, int length) {
	kfiber_file* file = (kfiber_file*)arg;
#ifdef BSD_OS
	length = aio_return(&file->iocb);
	//int err = aio_error(&file->iocb);
#endif
	if (length > 0) {
		file->st.offset += length;
	}
	kfiber* fiber = (kfiber*)data;
	kfiber_wakeup(fiber, fiber, length);
	return kev_fiber_ok;
}
int64_t kfiber_file_size(kfiber_file * fp) {
	return kfsize(kasync_file_get_handle(fp));
}
int kfiber_file_read(kfiber_file * file, char* buf, int length) {
	kfiber* fiber = kselector_get_fiber(kasync_file_get_selector(file));
	CHECK_FIBER(fiber);
	kasync_file_bind_opaque(file, fiber);
	assert(kasync_file_get_selector(file) == fiber->base.selector);
	if (!kgl_selector_module.aio_read(file, kfiber_file_callback, buf, length, file)) {
		return -1;
	}
	return __kfiber_wait(fiber, fiber);
}
int kfiber_file_write(kfiber_file * file, const char* buf, int length) {
	kfiber* fiber = kselector_get_fiber(kasync_file_get_selector(file));
	kasync_file_bind_opaque(file, fiber);
	CHECK_FIBER(fiber);
	assert(kasync_file_get_selector(file) == fiber->base.selector);
	if (!kgl_selector_module.aio_write(file, kfiber_file_callback, buf, length, file)) {
		return -1;
	}
	return __kfiber_wait(fiber, fiber);
}
int kfiber_file_seek(kfiber_file * file, seekPosion pos, int64_t offset) {
	switch (pos) {
	case seekBegin:
		file->st.offset = offset;
		return 0;
	case seekCur:
		file->st.offset += offset;
		return 0;
	default:
		return -1;
	}
}
int64_t kfiber_file_tell(kfiber_file * file) {
	return file->st.offset;
}
void kfiber_file_close(kfiber_file * file) {
	kasync_file_close(file);
	xfree(file);
}
KTHREAD_FUNCTION _kfiber_worker_thread(void* arg) {
	kfiber* fiber = (kfiber*)arg;
	int result = fiber->start(fiber->arg, fiber->retval);
	kfiber_wakeup2(fiber->base.selector, fiber, fiber->arg, result);
	KTHREAD_RETURN;
}
int kfiber_thread_call(kfiber_start_func start, void* arg, int argc, int* ret) {
	kfiber* fiber = kfiber_self2();
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
typedef struct _kfiber_file_safe_param {
	kfiber_file* fp;
	void* buf;
	int* length;
} kfiber_file_safe_param;

int kfiber_file_safe_write_func(void* arg, int len) {
	kfiber_file_safe_param* param = (kfiber_file_safe_param*)arg;
	return (int)kfiber_file_write_full(param->fp, (const char*)param->buf, param->length);
}
int kfiber_file_safe_read_func(void* arg, int len) {
	kfiber_file_safe_param* param = (kfiber_file_safe_param*)arg;
	return kfiber_file_read(param->fp, (char*)param->buf, *param->length);
}
bool kfiber_file_safe_write_full(kfiber_file * fp, const char* buf, int* length) {
	kfiber* fiber = kfiber_self2();
	kselector* selector = kasync_file_get_selector(fp);
	if (selector == fiber->base.selector) {
		return kfiber_file_write_full(fp, buf, length);
	}
	kfiber_file_safe_param param;
	param.fp = fp;
	param.buf = (void*)buf;
	param.length = length;
	kfiber* ret_fiber = NULL;
	int ret = 0;
	if (kfiber_create2(selector, kfiber_file_safe_write_func, &param, 0, 0, &ret_fiber) != 0) {
		return false;
	}
	assert(ret_fiber);
	kfiber_join(ret_fiber, &ret);
	return !!ret;
}
int kfiber_file_safe_read(kfiber_file * fp, char* buf, int length) {
	kfiber* fiber = kfiber_self2();
	kselector* selector = kasync_file_get_selector(fp);
	if (selector == fiber->base.selector) {
		return kfiber_file_read(fp, buf, length);
	}
	kfiber_file_safe_param param;
	param.fp = fp;
	param.buf = (void*)buf;
	param.length = &length;
	kfiber* ret_fiber = NULL;
	int ret = 0;
	if (kfiber_create2(selector, kfiber_file_safe_read_func, &param, 0, 0, &ret_fiber) != 0) {
		return false;
	}
	assert(ret_fiber);
	kfiber_join(ret_fiber, &ret);
	return ret;
}
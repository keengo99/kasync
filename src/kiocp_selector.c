#ifdef _WIN32
#include <assert.h>
#include "kselector.h"
#include "ksocket.h"
#include "kserver.h"
#include "kasync_file.h"
#include "kmalloc.h"
#include "klog.h"
#include "kfiber.h"

#define MAXSENDBUF  32
#define MAXEVENT	256	

typedef BOOL(WINAPI *GetQueuedCompletionStatusEx_fn)(
	__in   HANDLE CompletionPort,
	__out  LPOVERLAPPED_ENTRY lpCompletionPortEntries,
	__in   ULONG ulCount,
	__out  PULONG ulNumEntriesRemoved,
	__in   DWORD dwMilliseconds,
	__in   BOOL fAlertable
	);
static GetQueuedCompletionStatusEx_fn pGetQueuedCompletionStatusEx = NULL;

static kev_result next_call_back(KOPAQUE data, void *arg, int got)
{
	kselectable *next_st = (kselectable *)arg;
	kev_result ret = next_st->e[OP_WRITE].result(next_st->data, next_st->e[OP_WRITE].arg, got);
	xfree(next_st);
	return ret;
}
bool kiocp_accept_ex(kserver_selectable *ss)
{
	kassert(!ksocket_opened(ss->accept_sockfd));
	ss->accept_sockfd = socket(ss->server->addr.v4.sin_family, SOCK_STREAM, 0);
	if (!ksocket_opened(ss->accept_sockfd)) {
		return false;
	}
	DWORD bytes_recv = 0;
	BOOL result = lpfnAcceptEx(
		ss->st.fd,
		ss->accept_sockfd,
		ss->tmp_addr_buf,
		0,
		sizeof(sockaddr_i) + 32,
		sizeof(sockaddr_i) + 32,
		&bytes_recv,
		&ss->st.e[OP_READ].lp);
	if (!result && WSAGetLastError() != ERROR_IO_PENDING) {
		ksocket_close(ss->accept_sockfd);
		ss->accept_sockfd = INVALID_SOCKET;
		return false;
	}
	KBIT_SET(ss->st.st_flags,STF_READ);
	return true;
}
static inline bool bind_iocp(HANDLE iocp,kselectable *st)
{
	if (KBIT_TEST(st->st_flags, STF_REV | STF_WEV)) {
		return true;
	}
	CreateIoCompletionPort((HANDLE)st->fd, iocp, (ULONG_PTR)st, 0);
	KBIT_SET(st->st_flags, STF_REV | STF_WEV);
	return true;
}
static void iocp_selector_bind(kselector *selector, kselectable *st)
{
	if (KBIT_TEST(st->st_flags, STF_REV | STF_WEV)) {
		kassert(st->selector == selector);
		return;
	}
	st->selector = selector;
	if (ksocket_opened(st->fd)) {
		CreateIoCompletionPort((HANDLE)st->fd, selector->ctx, (ULONG_PTR)st, 0);
	}
	KBIT_SET(st->st_flags, STF_REV | STF_WEV);
}
static void iocp_selector_init(kselector *selector)
{
	selector->ctx = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, (ULONG_PTR)NULL, 0);
}

static void iocp_selector_remove(kselector *selector, kselectable *st)
{
#if 0
	if (!KBIT_TEST(st->st_flags, STF_REV | STF_WEV)) {
		//socket not set event
		return;
	}
	if (pNtSetInformationFile == NULL) {
		return;
	}
	kselector_remove_list(selector, st);
	SOCKET sockfd = st->fd;
	FILE_COMPLETION_INFORMATION ci;
	IO_STATUS_BLOCK io_status;
	memset(&io_status, 0, sizeof(io_status));
	memset(&ci, 0, sizeof(ci));
	ci.Key = NULL;
	ci.Port = NULL;
	NTSTATUS ret = pNtSetInformationFile((HANDLE)st->fd, &io_status, &ci, sizeof(ci), FileReplaceCompletionInformation);
	printf("ntsetinfomationfile ret=[%x]\n", ret);
#endif
}
static bool iocp_selector_recvfrom(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, buffer_callback addr_buffer, void *arg)
{
	kassert(KBIT_TEST(st->st_flags, STF_READ|STF_WRITE| STF_RECVFROM) == 0);
	KBIT_SET(st->st_flags, STF_RECVFROM);
	DWORD BytesRecv = 0;
	DWORD Flags = 0;
	WSABUF buf[16];
	WSABUF addr;
	st->e[OP_READ].arg = arg;
	st->e[OP_READ].result = result;

	int bc = buffer(st->data,arg, buf, 16);
	addr_buffer(st->data,arg, &addr, 1);
	int rc = WSARecvFrom(st->fd, buf, bc, &BytesRecv, &Flags, (struct sockaddr *)addr.buf,(INT *)&addr.len, &st->e[OP_READ].lp, NULL);
	if (rc == SOCKET_ERROR) {
		int err = WSAGetLastError();
		if (WSA_IO_PENDING != err) {
			KBIT_CLR(st->st_flags, STF_RECVFROM);
			return false;
		}
	}
	if (st->queue.next == NULL) {
		kselector_add_list(selector, st, KGL_LIST_RW);
	}
	return true;
}
static bool iocp_selector_read(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	kassert(KBIT_TEST(st->st_flags, STF_READ) == 0);
	KBIT_SET(st->st_flags,STF_READ);
	WSABUF recvBuf[MAXSENDBUF];
	memset(&recvBuf, 0, sizeof(recvBuf));
	int bufferCount;
	if (buffer) {
		bufferCount = buffer(st->data,arg, recvBuf, MAXSENDBUF);
	} else {
		bufferCount = 1;
	}
	DWORD BytesRecv = 0;
	DWORD Flags = 0;
	st->e[OP_READ].arg = arg;
	st->e[OP_READ].result = result;
	st->e[OP_READ].buffer = buffer;
	bind_iocp(selector->ctx, st);
	int rc = WSARecv(st->fd, recvBuf, bufferCount, &BytesRecv, &Flags, &st->e[OP_READ].lp, NULL);
#ifndef NDEBUG
	//klog(KLOG_DEBUG,"addSocket st=%p,us=%p,op=%d,rc=%d,err=%d\n",s,us,op,rc,err);
#endif
	if (rc == SOCKET_ERROR) {
		int err = WSAGetLastError();
		if (WSA_IO_PENDING != err) {
			KBIT_CLR(st->st_flags, STF_READ);
			return false;
		}
	}
	if (st->queue.next == NULL) {
		kselector_add_list(selector, st, KGL_LIST_RW);
	}
	return true;
}
static bool iocp_selector_write(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	KBIT_SET(st->st_flags,STF_WRITE);
	WSABUF recvBuf[MAXSENDBUF];
	memset(&recvBuf, 0, sizeof(recvBuf));
	int bufferCount;
	if (buffer) {
		bufferCount = buffer(st->data,arg, recvBuf, MAXSENDBUF);
		kassert(recvBuf[0].len > 0);
	} else {
		bufferCount = 1;
	}
	//printf("iocp write bc=[%d],data_len=[%d]\n", bufferCount,recvBuf[0].len);
	DWORD BytesRecv = 0;
	DWORD Flags = 0;
	st->e[OP_WRITE].arg = arg;
	st->e[OP_WRITE].result = result;
	st->e[OP_WRITE].buffer = buffer;
	bind_iocp(selector->ctx, st);
	int rc = WSASend(st->fd, recvBuf, bufferCount, &BytesRecv, Flags, &st->e[OP_WRITE].lp, NULL);
#ifndef NDEBUG
	//klog(KLOG_DEBUG,"addSocket st=%p,rc=%d\n",st,rc);
#endif
	if (rc == SOCKET_ERROR) {
		int err = WSAGetLastError();
		if (WSA_IO_PENDING != err) {
			KBIT_CLR(st->st_flags, STF_WRITE);
			return false;
		}
	}
	if (st->queue.next == NULL) {
		kselector_add_list(selector, st, KGL_LIST_RW);
	}
	return true;
}
static bool iocp_selector_connect(kselector *selector, kselectable *st, result_callback result, void *arg)
{
	//printf("connection st=[%p]\n", st);
	kassert(KBIT_TEST(st->st_flags, STF_WRITE) == 0);
	WSABUF addr_buf;
	st->e[OP_READ].buffer(st->data, st->e[OP_READ].arg, &addr_buf, 1);
	KBIT_SET(st->st_flags,STF_WRITE);
	st->e[OP_WRITE].arg = arg;
	st->e[OP_WRITE].result = result;
	st->e[OP_WRITE].buffer = NULL;
	//CreateIoCompletionPort((HANDLE)st->fd, selector->ctx, (ULONG_PTR)st, 0);
	DWORD BytesRecv = 0;
	int rc = lpfnConnectEx(st->fd, (struct sockaddr *)addr_buf.buf, addr_buf.len, NULL, 0, &BytesRecv, &st->e[OP_WRITE].lp);
	if (rc == FALSE) {
		int err = WSAGetLastError();
		if (WSA_IO_PENDING != err) {
			KBIT_CLR(st->st_flags, STF_WRITE);
			return false;
		}
	}
	kassert(st->queue.next == NULL);
	kselector_add_list(selector,st, KGL_LIST_CONNECT);
	return true;
}
static kev_result iocp_accept_result(KOPAQUE data, void *arg, int got)
{
	kserver_selectable *ss = (kserver_selectable *)arg;
	if (got == 0) {
		setsockopt(ss->accept_sockfd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&ss->st.fd, sizeof(ss->st.fd));
		ss->addr_len = sizeof(ss->accept_addr);
		getpeername(ss->accept_sockfd, (struct sockaddr *)&ss->accept_addr, &ss->addr_len);
	}
	kev_result ret = ss->st.e[OP_WRITE].result(data, ss->st.e[OP_WRITE].arg, got);
	if (!KEV_AVAILABLE(ret)) {
		return ret;
	}
	do {
		if (ss->server->closed) {
			kserver_release(ss->server);
			return kev_destroy;
		}
	} while (!kiocp_accept_ex(ss));

	return kev_ok;
}
static bool iocp_selector_listen(kselector *selector, kserver_selectable *ss, result_callback result)
{
	bind_iocp(selector->ctx, &ss->st);
	ss->st.e[OP_READ].arg = ss;
	ss->st.e[OP_READ].result = iocp_accept_result;

	ss->st.e[OP_WRITE].arg = ss;
	ss->st.e[OP_WRITE].result = result;
	return kiocp_accept_ex(ss);
}
static void iocp_selector_next(kselector *selector, KOPAQUE data, result_callback result, void *arg, int got)
{
	kselectable *next_st = (kselectable *)xmalloc(sizeof(kselectable));
	memset(next_st, 0, sizeof(kselectable));
	next_st->selector = selector;
	next_st->data = data;
	KBIT_SET(next_st->st_flags,STF_READ);

	next_st->e[OP_READ].arg = next_st;
	next_st->e[OP_READ].result = next_call_back;
	next_st->e[OP_READ].buffer = NULL;

	next_st->e[OP_WRITE].arg = arg;
	next_st->e[OP_WRITE].result = result;
	next_st->e[OP_WRITE].buffer = NULL;
	if (!PostQueuedCompletionStatus(selector->ctx, got, (ULONG_PTR)next_st, &next_st->e[OP_READ].lp)) {
		KBIT_CLR(next_st->st_flags, STF_READ);
		xfree(next_st);
		perror("notice error");
	}
}
void iocp_selector_aio_open(kselector *selector, kasync_file *aio_file, FILE_HANDLE fd)
{
	kassert(kselector_is_same_thread(selector));
	//kasync_file *aio_file = xmemory_new(kasync_file);
	//memset(aio_file, 0, sizeof(kasync_file));
	aio_file->st.fd = (SOCKET)fd;
	bind_iocp(selector->ctx, &aio_file->st);
	aio_file->st.selector = selector;
	return;
}
bool iocp_selector_aio_write(kselector *selector, kasync_file *file, char *buf, int64_t offset, int length, aio_callback cb, void *arg)
{
	kassert(kfiber_check_file_callback(cb));
	assert(file->cb == NULL);
	katom_inc((void *)&kgl_aio_count);
	file->buf = buf;
	file->arg = arg;
	file->cb = cb;
	LARGE_INTEGER *li = (LARGE_INTEGER *)&file->st.e[OP_WRITE].lp.Pointer;
	li->QuadPart = offset;
	DWORD bytesWrite;
	KBIT_SET(file->st.st_flags, STF_WRITE);
	file->st.e[OP_WRITE].result = result_async_file_event;
	file->st.e[OP_WRITE].arg = file;
	file->st.e[OP_WRITE].buffer = NULL;
	BOOL ret = WriteFile((FILE_HANDLE)file->st.fd, buf, length, &bytesWrite, &file->st.e[OP_WRITE].lp);
	if (!ret) {
		int err = WSAGetLastError();
		if (err != ERROR_IO_PENDING) {
			katom_dec((void *)&kgl_aio_count);
			KBIT_CLR(file->st.st_flags, STF_WRITE);
			file->cb = NULL;
			return false;
		}
	}
	return true;
}
bool iocp_selector_aio_read(kselector *selector, kasync_file *file, char *buf, int64_t offset, int length, aio_callback cb, void *arg)
{
	kassert(kfiber_check_file_callback(cb));
	assert(file->cb == NULL);
	katom_inc((void *)&kgl_aio_count);
	file->buf = buf;
	file->arg = arg;
	file->cb = cb;
	LARGE_INTEGER *li = (LARGE_INTEGER *)&file->st.e[OP_READ].lp.Pointer;
	li->QuadPart = offset;
	DWORD bytesRead;
	KBIT_SET(file->st.st_flags, STF_READ);
	file->st.e[OP_READ].result = result_async_file_event;
	file->st.e[OP_READ].arg = file;
	file->st.e[OP_READ].buffer = NULL;
	BOOL ret = ReadFile((FILE_HANDLE)file->st.fd, buf, length, &bytesRead, &file->st.e[OP_READ].lp);
	if (!ret) {
		int err = WSAGetLastError();
		if (err != ERROR_IO_PENDING) {
			katom_dec((void *)&kgl_aio_count);
			KBIT_CLR(file->st.st_flags, STF_READ);
			file->cb = NULL;			
			return false;
		}
	}
	return true;
}
static void handle_complete_event(kselector *selector,kselectable *st, BOOL result, DWORD recvBytes, OVERLAPPED *evlp)
{
	//printf("handle_complete_event st=[%p]\n", st);
	if (KBIT_TEST(st->st_flags, STF_READ | STF_WRITE) == (STF_READ | STF_WRITE)) {
		//reset active_msec
		if (!KBIT_TEST(st->st_flags, STF_RREADY2 | STF_WREADY2)) {
			kselector_add_list(selector, st, KGL_LIST_RW);
		}
	} else {
		kselector_remove_list(selector,st);
	}
	if (evlp == &st->e[OP_READ].lp) {
		//printf("handle read event st=[%p]\n", st);
		kassert(KBIT_TEST(st->st_flags, STF_READ|STF_RECVFROM));
		KBIT_CLR(st->st_flags, STF_READ|STF_RECVFROM);
		kassert(!KBIT_TEST(st->st_flags, STF_RREADY|STF_RREADY2));
		st->e[OP_READ].result(st->data, st->e[OP_READ].arg, (result ? recvBytes : -1));
		return;
	}
	if (evlp == &st->e[OP_WRITE].lp) {
		//printf("handle write event st=[%p]\n", st);
		kassert(KBIT_TEST(st->st_flags, STF_WRITE));
		KBIT_CLR(st->st_flags, STF_WRITE);
		kassert(!KBIT_TEST(st->st_flags, STF_WREADY|STF_WREADY2));
		st->e[OP_WRITE].result(st->data, st->e[OP_WRITE].arg, (result ? recvBytes : -1));
		return;
	}
	kassert(false);
}
static int iocp_selector_selectx(kselector *selector)
{
	OVERLAPPED_ENTRY oe[MAXEVENT];
	DWORD ret = 0;
	memset(oe, 0, sizeof(oe));
	BOOL result = pGetQueuedCompletionStatusEx(selector->ctx, oe, MAXEVENT, &ret, SELECTOR_TMO_MSEC, TRUE);
	if (selector->utm) {
		kselector_update_time();
	}
	for (int i = 0; i < (int)ret; i++) {
		kselectable *st = (kselectable *)(oe[i].lpCompletionKey);
		if (st) {
			handle_complete_event(selector,st, ((DWORD)(oe[i].Internal)) == 0, oe[i].dwNumberOfBytesTransferred, oe[i].lpOverlapped);
		}
	}
	return (int)ret;
}
static int iocp_selector_select(kselector *selector)
{
	assert(pGetQueuedCompletionStatusEx == NULL);
	DWORD recvBytes = 0;
	OVERLAPPED *evlp;	
	kselectable *st = NULL;
	BOOL result = GetQueuedCompletionStatus(selector->ctx, &recvBytes, (PULONG_PTR)&st, (LPOVERLAPPED *)&evlp, SELECTOR_TMO_MSEC);
	if (selector->utm) {
		kselector_update_time();
	}
	if (st) {
		handle_complete_event(selector,st, result, recvBytes, evlp);
	}
	return (int)result;
}
static void iocp_selector_destroy(kselector *selector)
{
	CloseHandle((HANDLE)selector->ctx);
}
static kselector_module iocp_selector_module = {
	"iocp",
	iocp_selector_init,
	iocp_selector_destroy,
	iocp_selector_bind,

	iocp_selector_listen,
	iocp_selector_connect,
	kselector_default_remove,
	iocp_selector_read,
	iocp_selector_write,
	kselector_default_readhup,
	kselector_default_remove_readhup,
	iocp_selector_recvfrom,

	iocp_selector_select,
	iocp_selector_next,
	iocp_selector_aio_open,
	iocp_selector_aio_write,
	iocp_selector_aio_read
};
void kiocp_module_init()
{
	kgl_selector_module = iocp_selector_module;
	pGetQueuedCompletionStatusEx = (GetQueuedCompletionStatusEx_fn)GetProcAddress(GetModuleHandle("kernel32.dll"), "GetQueuedCompletionStatusEx");
	if (pGetQueuedCompletionStatusEx) {
		kgl_selector_module.select = iocp_selector_selectx;
	}
}
#endif

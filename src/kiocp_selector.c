#ifdef _WIN32
#include <assert.h>

#include "kselector.h"
#include "ksocket.h"
#include "kserver.h"
#include "kasync_file.h"
#include "kmalloc.h"
#include "klog.h"
#include "kfiber.h"
#include "kudp.h"

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
	KBIT_SET(ss->st.base.st_flags,STF_READ);
	return true;
}
static void iocp_selector_bind(kselector *selector, kselectable *st)
{
	assert(!KBIT_TEST(st->base.st_flags, STF_IOCP_BINDED));
	if (KBIT_TEST(st->base.st_flags, STF_IOCP_BINDED)) {
		kassert(st->base.selector == selector);
		return;
	}
	if (ksocket_opened(st->fd)) {
		CreateIoCompletionPort((HANDLE)st->fd, selector->ctx, (ULONG_PTR)st, 0);
		/*
		if (KBIT_TEST(st->base.st_flags, STF_UDP)) {
			SetFileCompletionNotificationModes((HANDLE)st->fd, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS);
		}
		*/
		KBIT_SET(st->base.st_flags, STF_IOCP_BINDED);
	}
	st->base.selector = selector;
}
static void iocp_selector_init(kselector *selector)
{
	selector->ctx = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, (ULONG_PTR)NULL, 0);
}

static void iocp_selector_remove(kselector *selector, kselectable *st)
{
#if 0
	if (!KBIT_TEST(st->base.st_flags, STF_REV | STF_WEV)) {
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
static int iocp_selector_recvmsg(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	kassert(KBIT_TEST(st->base.st_flags, STF_UDP));
	DWORD BytesRecv = 0;
	DWORD Flags = 0;
	WSABUF buf[MAX_IOVECT_COUNT];
	WSABUF addr;
	st->e[OP_READ].arg = arg;
	st->e[OP_READ].result = result;
	kconnection* c = kgl_list_data(st, kconnection, st);
	int bc = 0;
	if (buffer != NULL) {
		bc = buffer(st->data, arg, buf, MAX_IOVECT_COUNT);
		kconnection_buffer_addr(st->data, st, &addr, 1);
	} else {
		addr.iov_base = NULL;
		addr.iov_len = 0;
	}
	int rc;
	if (c->udp) {
		memset(c->udp, 0, sizeof(kudp_extend));		
		c->udp->msg.name = (struct sockaddr*)addr.buf;
		c->udp->msg.namelen = (INT)addr.len;
		c->udp->msg.lpBuffers = buf;
		c->udp->msg.dwBufferCount = bc;

		c->udp->msg.Control.iov_base = c->udp->pktinfo;
		c->udp->msg.Control.iov_len = sizeof(c->udp->pktinfo);
		rc = lpfnWsaRecvMsg(st->fd, &c->udp->msg, &BytesRecv, &st->e[OP_READ].lp, NULL);
	} else {
		rc = WSARecvFrom(st->fd, buf, bc, &BytesRecv, &Flags, (struct sockaddr*)addr.buf, (INT*)&addr.len, &st->e[OP_READ].lp, NULL);
	}
	return rc;
}

static bool iocp_selector_read(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	kassert(KBIT_TEST(st->base.st_flags, STF_READ) == 0);
	KBIT_SET(st->base.st_flags,STF_READ);
	int rc;
	if (KBIT_TEST(st->base.st_flags, STF_UDP)) {
		rc = iocp_selector_recvmsg(selector, st, result, buffer, arg);
	} else {
		WSABUF recvBuf[MAX_IOVECT_COUNT];
		memset(&recvBuf, 0, sizeof(recvBuf));
		int bufferCount;
		if (buffer) {
			bufferCount = buffer(st->data, arg, recvBuf, MAX_IOVECT_COUNT);
		} else {
			bufferCount = 1;
		}
		DWORD BytesRecv = 0;
		DWORD Flags = 0;
		st->e[OP_READ].arg = arg;
		st->e[OP_READ].result = result;
		st->e[OP_READ].buffer = buffer;
		assert(st->base.selector == selector);
		if (!KBIT_TEST(st->base.st_flags, STF_IOCP_BINDED)) {
			assert(false);
		}
		assert(KBIT_TEST(st->base.st_flags, STF_IOCP_BINDED));
		//iocp_selector_bind(selector, st);
		rc = WSARecv(st->fd, recvBuf, bufferCount, &BytesRecv, &Flags, &st->e[OP_READ].lp, NULL);
#ifndef NDEBUG
		//klog(KLOG_DEBUG,"addSocket st=%p,us=%p,op=%d,rc=%d,err=%d\n",s,us,op,rc,err);
#endif
	}
	if (rc == SOCKET_ERROR) {
		int err = WSAGetLastError();
		if (WSA_IO_PENDING != err) {
			KBIT_CLR(st->base.st_flags, STF_READ);
			return false;
		}
	}
	if (st->base.queue.next == NULL) {
		kselector_add_list(selector, st, KGL_LIST_RW);
	}
	return true;
}
static bool iocp_selector_write(kselector *selector, kselectable *st, result_callback result, buffer_callback buffer, void *arg)
{
	KBIT_SET(st->base.st_flags,STF_WRITE);
	WSABUF recvBuf[MAX_IOVECT_COUNT];
	memset(&recvBuf, 0, sizeof(recvBuf));
	int bufferCount;
	if (buffer) {
		bufferCount = buffer(st->data,arg, recvBuf, MAX_IOVECT_COUNT);
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
	assert(st->base.selector == selector);
	assert(KBIT_TEST(st->base.st_flags, STF_IOCP_BINDED));
	int rc = WSASend(st->fd, recvBuf, bufferCount, &BytesRecv, Flags, &st->e[OP_WRITE].lp, NULL);
#ifndef NDEBUG
	//klog(KLOG_DEBUG,"addSocket st=%p,rc=%d\n",st,rc);
#endif
	if (rc == SOCKET_ERROR) {
		int err = WSAGetLastError();
		if (WSA_IO_PENDING != err) {
			KBIT_CLR(st->base.st_flags, STF_WRITE);
			return false;
		}
	}
	if (st->base.queue.next == NULL) {
		kselector_add_list(selector, st, KGL_LIST_RW);
	}
	return true;
}
static bool iocp_selector_connect(kselector *selector, kselectable *st, result_callback result, void *arg)
{
	//printf("connection st=[%p]\n", st);
	kassert(KBIT_TEST(st->base.st_flags, STF_WRITE) == 0);
	WSABUF addr_buf;
	st->e[OP_READ].buffer(st->data, st->e[OP_READ].arg, &addr_buf, 1);
	KBIT_SET(st->base.st_flags,STF_WRITE);
	st->e[OP_WRITE].arg = arg;
	st->e[OP_WRITE].result = result;
	st->e[OP_WRITE].buffer = NULL;
	//CreateIoCompletionPort((HANDLE)st->fd, selector->ctx, (ULONG_PTR)st, 0);
	DWORD BytesRecv = 0;
	int rc = lpfnConnectEx(st->fd, (struct sockaddr *)addr_buf.buf, addr_buf.len, NULL, 0, &BytesRecv, &st->e[OP_WRITE].lp);
	if (rc == FALSE) {
		int err = WSAGetLastError();
		if (WSA_IO_PENDING != err) {
			KBIT_CLR(st->base.st_flags, STF_WRITE);
			return false;
		}
	}
	kassert(st->base.queue.next == NULL);
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
	return ss->st.e[OP_WRITE].result(data, ss->st.e[OP_WRITE].arg, got);
}
static bool iocp_selector_accept(kserver_selectable* ss, void *arg)
{
	assert(KBIT_TEST(ss->st.base.st_flags, STF_IOCP_BINDED));
	ss->st.e[OP_WRITE].arg = arg;
	do {
		if (!KBIT_TEST(ss->server->flags, KGL_SERVER_START)) {
			return false;
		}
	} while (!kiocp_accept_ex(ss));
	return true;
}
static bool iocp_selector_listen(kserver_selectable *ss, result_callback result)
{
	assert(KBIT_TEST(ss->st.base.st_flags, STF_IOCP_BINDED));
	ss->st.e[OP_READ].arg = ss;
	ss->st.e[OP_READ].result = iocp_accept_result;

	ss->st.e[OP_WRITE].result = result;
	return true;
}
static void iocp_selector_next(kselector *selector, KOPAQUE data, result_callback result, void *arg, int got)
{
	kselectable *next_st = (kselectable *)xmalloc(sizeof(kselectable));
	memset(next_st, 0, sizeof(kselectable));
	next_st->base.selector = selector;
	next_st->data = data;
	KBIT_SET(next_st->base.st_flags,STF_READ);

	next_st->e[OP_READ].arg = next_st;
	next_st->e[OP_READ].result = next_call_back;
	next_st->e[OP_READ].buffer = NULL;

	next_st->e[OP_WRITE].arg = arg;
	next_st->e[OP_WRITE].result = result;
	next_st->e[OP_WRITE].buffer = NULL;
	if (!PostQueuedCompletionStatus(selector->ctx, got, (ULONG_PTR)next_st, &next_st->e[OP_READ].lp)) {
		KBIT_CLR(next_st->base.st_flags, STF_READ);
		xfree(next_st);
		perror("notice error");
	}
}

void iocp_selector_aio_open(kselector *selector, kasync_file *aio_file, FILE_HANDLE fd)
{
	kassert(kselector_is_same_thread(selector));
#ifndef KF_ASYNC_WORKER
	aio_file->st.fd = (SOCKET)fd;
	iocp_selector_bind(selector, &aio_file->st);
	aio_file->st.base.selector = selector;
#else
	aio_file->fd = fd;
	aio_file->selector = selector;
#endif
	return;
}
bool iocp_selector_aio_write(kasync_file *file, result_callback result, const char *buf, int length, void* arg)
{
	assert(KBIT_TEST(file->st.base.st_flags,STF_AIO_FILE));
	assert(KBIT_TEST(file->st.base.st_flags, STF_WRITE|STF_READ)==0);	
	file->st.e[OP_WRITE].result = result;
	file->st.e[OP_WRITE].arg = arg;
	file->st.e[OP_WRITE].buffer = NULL;
#ifndef KF_ASYNC_WORKER
	KBIT_SET(file->st.base.st_flags, STF_WRITE);
	DWORD bytesWrite;
	LARGE_INTEGER *li = (LARGE_INTEGER *)&file->st.e[OP_WRITE].lp.Pointer;
	li->QuadPart = file->st.offset;
	BOOL ret = WriteFile(kasync_file_get_handle(file), buf, length, &bytesWrite, &file->st.e[OP_WRITE].lp);
	if (!ret) {
		int err = WSAGetLastError();
		if (err != ERROR_IO_PENDING) {
			KBIT_CLR(file->st.base.st_flags, STF_WRITE);
			return false;
		}
	}
	return true;
#else
	file->kiocb.length = length;
	file->kiocb.buf = (char*)buf;
	file->kiocb.cmd = kf_aio_write;
	return kasync_file_worker_start(file);
#endif
}
bool iocp_selector_aio_read(kasync_file *file, result_callback result, char *buf, int length, void *arg)
{
	assert(KBIT_TEST(file->st.base.st_flags, STF_WRITE | STF_READ) == 0);	
	file->st.e[OP_READ].result = result;
	file->st.e[OP_READ].arg = arg;
	file->st.e[OP_READ].buffer = NULL;
#ifndef KF_ASYNC_WORKER
	KBIT_SET(file->st.base.st_flags, STF_READ);
	LARGE_INTEGER *li = (LARGE_INTEGER *)&file->st.e[OP_READ].lp.Pointer;
	li->QuadPart = file->st.offset;
	DWORD bytesRead;
	BOOL ret = ReadFile(kasync_file_get_handle(file), buf, length, &bytesRead, &file->st.e[OP_READ].lp);
	if (!ret) {
		int err = WSAGetLastError();
		if (err != ERROR_IO_PENDING) {
			KBIT_CLR(file->st.base.st_flags, STF_READ);
			return false;
		}
	}
	return true;
#else
	file->kiocb.length = length;
	file->kiocb.buf = (char*)buf;
	file->kiocb.cmd = kf_aio_read;
	return kasync_file_worker_start(file);
#endif
}
bool iocp_selector_sendfile(kselectable* st, result_callback result, buffer_callback buffer, void* arg) {
#ifdef KSOCKET_SSL
	assert(st->ssl == NULL);
#endif
	assert(!KBIT_TEST(st->base.st_flags, STF_WRITE));
	KBIT_SET(st->base.st_flags, STF_WRITE);
	//printf("iocp write bc=[%d],data_len=[%d]\n", bufferCount,recvBuf[0].len);
	DWORD BytesRecv = 0;
	DWORD Flags = 0;
	st->e[OP_WRITE].arg = arg;
	st->e[OP_WRITE].result = result;
	WSABUF bufs;
	buffer(st->data, arg, &bufs, 1);
	kasync_file* file = (kasync_file *)bufs.iov_base;
	LARGE_INTEGER* li = (LARGE_INTEGER*)&st->e[OP_WRITE].lp.Pointer;
	li->QuadPart = file->st.offset;
	int rc = lpfnTransmitFile(st->fd, kasync_file_get_handle(file), bufs.iov_len, 0, &st->e[OP_WRITE].lp, NULL, 0);
	if (rc == FALSE) {
		int err = WSAGetLastError();
		if (WSA_IO_PENDING != err) {
			KBIT_CLR(st->base.st_flags, STF_WRITE);
			return false;
		}
	}
	if (st->base.queue.next == NULL) {
		kselector_add_list(st->base.selector, st, KGL_LIST_RW);
	}
	return true;
}
static void handle_complete_event(kselector *selector,kselectable *st, BOOL result, DWORD recvBytes, OVERLAPPED *evlp)
{
	//printf("handle_complete_event st=[%p]\n", st);
	if (KBIT_TEST(st->base.st_flags, STF_READ | STF_WRITE) == (STF_READ | STF_WRITE)) {
		//reset active_msec
		if (!KBIT_TEST(st->base.st_flags, STF_RREADY2 | STF_WREADY2)) {
			kselector_add_list(selector, st, KGL_LIST_RW);
		}
	} else {
		kselector_remove_list(selector,st);
	}
	if (evlp == &st->e[OP_READ].lp) {
		//printf("handle read event st=[%p]\n", st);
		kassert(KBIT_TEST(st->base.st_flags, STF_READ));
		KBIT_CLR(st->base.st_flags, STF_READ);
		kassert(!KBIT_TEST(st->base.st_flags, STF_RREADY|STF_RREADY2));
		st->e[OP_READ].result(st->data, st->e[OP_READ].arg, (result ? recvBytes : -1));
		return;
	}
	if (evlp == &st->e[OP_WRITE].lp) {
		//printf("handle write event st=[%p]\n", st);
		kassert(KBIT_TEST(st->base.st_flags, STF_WRITE));
		KBIT_CLR(st->base.st_flags, STF_WRITE);
		kassert(!KBIT_TEST(st->base.st_flags, STF_WREADY|STF_WREADY2));
		st->e[OP_WRITE].result(st->data, st->e[OP_WRITE].arg, (result ? recvBytes : -1));
		return;
	}
	kassert(false);
}
static int iocp_selector_selectx(kselector *selector,int tmo)
{
	OVERLAPPED_ENTRY oe[MAXEVENT];
	DWORD ret = 0;
	memset(oe, 0, sizeof(oe));
	BOOL result = pGetQueuedCompletionStatusEx(selector->ctx, oe, MAXEVENT, &ret, tmo, TRUE);
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
static int iocp_selector_select(kselector *selector,int tmo)
{
	assert(pGetQueuedCompletionStatusEx == NULL);
	DWORD recvBytes = 0;
	OVERLAPPED *evlp;	
	kselectable *st = NULL;

	BOOL result = GetQueuedCompletionStatus(selector->ctx, &recvBytes, (PULONG_PTR)&st, (LPOVERLAPPED *)&evlp, tmo);
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
	iocp_selector_accept,
	iocp_selector_connect,
	kselector_default_remove,
	iocp_selector_read,
	iocp_selector_write,
	kselector_default_readhup,
	kselector_default_remove_readhup,
	iocp_selector_select,
	iocp_selector_next,
	iocp_selector_aio_open,
	iocp_selector_aio_write,
	iocp_selector_aio_read,
	iocp_selector_sendfile
};
void kiocp_module_init()
{
	auto module_handle = GetModuleHandleA("kernel32.dll");
	kgl_selector_module = iocp_selector_module;
	pGetQueuedCompletionStatusEx = (GetQueuedCompletionStatusEx_fn)GetProcAddress(module_handle, "GetQueuedCompletionStatusEx");
	if (pGetQueuedCompletionStatusEx) {
		kgl_selector_module.select = iocp_selector_selectx;
	}
}
#endif

#include <sysdep.h>
#include <errno.h>
#ifdef __cplusplus
extern "C" {
#endif
	long __syscall_error(long err);
#ifdef __cplusplus
}
#endif


/* This routine is jumped to by all the syscall handlers, to stash
   an error number into errno.  */
long	__syscall_error(long err)
{
	errno = -err;
	return -1;
}


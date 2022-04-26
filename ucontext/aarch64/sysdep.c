#include <sysdep.h>
#include <errno.h>

long __syscall_error(long err);

/* This routine is jumped to by all the syscall handlers, to stash
   an error number into errno.  */
long	__syscall_error(long err)
{
	errno = -err;
	return -1;
}


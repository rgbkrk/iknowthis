#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Apply or remove an advisory lock on an open file.
// int flock(int fd, int operation);
SYSFUZZ(flock, __NR_flock, SYS_NONE, CLONE_DEFAULT, 0)
{
	return spawn_syscall_lwp(this, NULL, __NR_flock,                                    // int
	                         typelib_fd_get(this),                                      // int fd
	                         typelib_get_integer());                                    // int operation
}


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

// Change working directory.
// int fchdir(int fd);
SYSFUZZ(fchdir, __NR_fchdir, SYS_NONE, CLONE_DEFAULT, 0)
{
	return syscall_fast(__NR_fchdir,                                                    // int
	                    typelib_fd_get(this));                                          // int fd
}

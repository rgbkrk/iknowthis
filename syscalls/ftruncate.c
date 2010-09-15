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

// Truncate a file to a specified length.
SYSFUZZ(ftruncate, __NR_ftruncate, SYS_NONE, CLONE_DEFAULT, 0)
{
	return spawn_syscall_lwp(this, NULL, __NR_ftruncate,                                // int
	                         typelib_fd_get(this),                                      // int fd
	                         typelib_get_integer());                                    // off_t length
}


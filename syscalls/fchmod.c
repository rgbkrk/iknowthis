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

// Change permissions of a file.
SYSFUZZ(fchmod, __NR_fchmod, SYS_NONE, CLONE_DEFAULT, 0)
{
	return spawn_syscall_lwp(this, NULL, __NR_fchmod,                                   // int
	                         typelib_fd_get(this),                                      // int fd
	                         typelib_get_integer());                                    // mode_t mode
}


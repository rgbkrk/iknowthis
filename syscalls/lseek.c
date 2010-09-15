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

// Reposition read/write file offset.
SYSFUZZ(lseek, __NR_lseek, SYS_NONE, CLONE_DEFAULT, 0)
{
	return spawn_syscall_lwp(this, NULL, __NR_lseek,           // off_t
	                         typelib_fd_get(this),             // int fd
	                         typelib_get_integer(),            // off_t offset
    	                     typelib_get_integer_range(0, 2)); // int whence
}


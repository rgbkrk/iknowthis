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

// Close a file descriptor.
SYSFUZZ(close, __NR_close, SYS_DISABLED, CLONE_DEFAULT, 0)
{
	gint   retcode;
	gint   fd;

    fd      = typelib_fd_get(this);

	retcode = spawn_syscall_lwp(this, NULL, __NR_close,                  // int
                                fd);                                     // int fd

    // If I closed it, report it as such.
    if (retcode == ESUCCESS) {
    	typelib_fd_stale(this, fd, FD_NONE);
    }

    return retcode;
}


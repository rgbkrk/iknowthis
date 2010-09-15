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

// Duplicate a file descriptor.
// int dup(int oldfd);
SYSFUZZ(dup, __NR_dup, SYS_NONE, CLONE_DEFAULT, 0)
{
	gint    fd;
	gint    retcode;

	retcode = spawn_syscall_lwp(this, &fd, __NR_dup,                                                // int
	                            typelib_fd_get(this));                                              // int oldfd

    if (retcode == ESUCCESS) {
        // Note that because basically nothing can go wrong with dup,
        // it will saturate all the available space in my fd list very
        // quickly.

        // Therefore, only allow it occassionally.
    	if (g_random_int_range(0, 1024)) {
    		// Throw it away.
    		close(fd);
        } else {
        	// Allow it.
        	typelib_fd_new(this, fd, FD_NONE);
        }
    }

    return retcode;
}

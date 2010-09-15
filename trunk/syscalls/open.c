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

// Open and possibly create a file or device.
SYSFUZZ(open, __NR_open, SYS_NONE, CLONE_DEFAULT, 1000)
{
	gchar *pathname;
	gint   retcode;
	gint   fd = -1;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, &fd, __NR_open,                       // int
                                     typelib_get_pathname(&pathname),       // const char *pathname
                                     typelib_get_integer(),                 // int flags
                                     typelib_get_integer());                // mode_t mode
    
    // Record the new file descriptor.
    if (retcode == ESUCCESS) {
    	typelib_fd_new(this, fd, FD_NONE);
    }

    // Release string.
    g_free(pathname);

    return retcode;
}


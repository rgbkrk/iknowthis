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

// Wait for some event on a file descriptor.
// int poll(struct pollfd *fds, nfds_t nfds, int timeout);
SYSFUZZ(poll, __NR_poll, SYS_NONE, CLONE_DEFAULT, 1000)
{
	gint        retcode;
	gpointer    fds;
	
    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_poll,                                      // int
                                typelib_get_buffer(&fds, g_random_int_range(0, PAGE_SIZE)), // struct pollfd *fds
                                typelib_get_integer(),                                      // nfds_t nfds
                                typelib_get_integer());                                     // int timeout

    // Clean up.
    typelib_clear_buffer(fds);

    return retcode;
}

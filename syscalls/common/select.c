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

// Synchronous I/O multiplexing.
SYSFUZZ(select, __NR_select, SYS_DISABLED, CLONE_DEFAULT, 1000)
{
    gpointer    readfds;
    gpointer    writefds;
    gpointer    exceptfds;
    gpointer    timeout;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_select,                                      // int
                                typelib_get_integer(),                                        // int nfds
                                typelib_get_buffer(&readfds, g_random_int_range(0, 1024)),    // fd_set *readfds
                                typelib_get_buffer(&writefds, g_random_int_range(0, 1024)),   // fd_set *writefds
                                typelib_get_buffer(&exceptfds, g_random_int_range(0, 1024)),  // fd_set *exceptfds
                                typelib_get_buffer(&timeout, g_random_int_range(0, 1024)));   // struct timeval *timeout

    typelib_clear_buffer(readfds);
    typelib_clear_buffer(writefds);
    typelib_clear_buffer(exceptfds);
    typelib_clear_buffer(timeout);

    return retcode;
}

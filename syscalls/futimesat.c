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

// Change timestamps of a file relative to a directory file descriptor.
// int futimesat(int dirfd, const char *pathname, const struct timeval times[2]);
SYSFUZZ(futimesat, __NR_futimesat, SYS_DISABLED, CLONE_DEFAULT, 0)
{
	gchar       *filename;
	gpointer     times;
    gint         retcode;

    retcode     = spawn_syscall_lwp(this, NULL, __NR_utimes,                                       // int
                                    typelib_fd_get(this),                                          // int dirfd
                                    typelib_get_pathname(&filename),                               // const char *filename
                                    typelib_get_buffer(&times, g_random_int_range(0, 0x1000)));    // const struct utimbuf *times

    typelib_clear_buffer(times);

    g_free(filename);

    return retcode;
}

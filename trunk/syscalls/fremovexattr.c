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

// Remove extended attribute.
// int fremovexattr(int fd, const char *name);
SYSFUZZ(fremovexattr, __NR_fremovexattr, SYS_NONE, CLONE_DEFAULT, 0)
{
    gint        retcode;
    gpointer    name;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_fremovexattr,                          // int
                                typelib_fd_get(this),                                   // int fd
                                typelib_get_buffer(&name, g_random_int_range(0, 8192)));// const char *name

    typelib_clear_buffer(name);

    return retcode;
}

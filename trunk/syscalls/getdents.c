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

// Get directory entries.
// int getdents(unsigned int fd, struct linux_dirent *dirp,
//              unsigned int count);
SYSFUZZ(getdents, __NR_getdents, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    dirp;
    gint        retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_getdents,                                  // int
                                typelib_fd_get(this),                                       // int fd
                                typelib_get_buffer(&dirp, g_random_int_range(0, 0x10000)),  // struct linux_dirent *dirp
                                typelib_get_integer());                                     // unsigned int count

    typelib_clear_buffer(dirp);

    return retcode;
}

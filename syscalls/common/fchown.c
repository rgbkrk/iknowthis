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

// Change ownership of a file.
// int fchown(int fd, uid_t owner, gid_t group);
SYSFUZZ(fchown, __NR_fchown, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_fchown,                                   // int
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),       // int fd
                             typelib_get_integer_selection(1, -1),                      // uid_t owner
                             typelib_get_integer_selection(1, -1));                     // gid_t group
}

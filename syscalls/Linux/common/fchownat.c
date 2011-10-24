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
// int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
SYSFUZZ(fchownat, __NR_fchownat, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_fchownat,                                 // int
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),       // int dirfd
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),       // int fd
                             typelib_get_integer(),                                     // uid_t owner
                             typelib_get_integer());                                    // gid_t group
}


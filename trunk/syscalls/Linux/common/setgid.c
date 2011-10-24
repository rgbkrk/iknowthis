#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set group identity.
// int setgid(gid_t gid);
SYSFUZZ(setgid, __NR_setgid, SYS_SAFE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_setgid,                                   // int
                             typelib_get_integer_selection(2, getgid(), getegid()));    // gid_t gid
}


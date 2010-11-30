#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set user identity.
// int setuid(uid_t uid);
SYSFUZZ(setuid, __NR_setuid, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    gint        uid;

    uid     = g_random_boolean() ?typelib_get_integer() : getuid();

    retcode = spawn_syscall_lwp(this, NULL, __NR_setuid,                                // int
                                uid);                                                   // uid_t uid

    if (retcode == ESUCCESS) {
        g_assert_cmpint(uid, !=, 0);
    }

    return retcode;
}


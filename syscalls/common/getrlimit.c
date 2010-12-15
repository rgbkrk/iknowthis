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
#include <sys/time.h>
#include <sys/resource.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get/set resource limits.
// int getrlimit(int resource, struct rlimit *rlim);
SYSFUZZ(getrlimit, __NR_getrlimit, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    rlim;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_getrlimit,                                 // int
                                typelib_get_integer_range(0, __RLIMIT_NLIMITS),             // int resource
                                typelib_get_buffer(&rlim, sizeof(struct rlimit)));          // struct rlimit *rlim

    typelib_clear_buffer(rlim);
    return retcode;
}


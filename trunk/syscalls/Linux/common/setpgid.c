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

// Set/get process group.
SYSFUZZ(setpgid, __NR_setpgid, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong   retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_setpgid,                                                                    // int
                                typelib_get_integer_selection(2, 0, typelib_get_resource(this, NULL, RES_FORK, RF_NONE)),    // pid_t pid
                                typelib_get_integer_selection(2, 0, typelib_get_resource(this, NULL, RES_FORK, RF_NONE)));   // pid_t pgid
    return retcode;
}


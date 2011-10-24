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
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set and get scheduling parameters.
// int sched_setparam(pid_t pid, const struct sched_param *param);
SYSFUZZ(sched_setparam, __NR_sched_setparam, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong                retcode;
    struct sched_param  *param;

    param = typelib_get_buffer(NULL, sizeof *param);

    param->sched_priority = typelib_get_integer_range(0, 128);

    retcode = spawn_syscall_lwp(this, NULL, __NR_sched_setparam,                                        // int
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),                    // pid_t pid
                                param);                                                                 // const struct sched_param *param

    typelib_clear_buffer(param);
    return retcode;
}


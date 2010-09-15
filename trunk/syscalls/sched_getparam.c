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
#include "resource.h"

// Set and get scheduling parameters.
// int sched_getparam(pid_t pid, struct sched_param *param);
SYSFUZZ(sched_getparam, __NR_sched_getparam, SYS_NONE, CLONE_DEFAULT, 0)
{
	gpointer    param;
	gint        retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_sched_getparam,                                        // int
	                            typelib_get_resource(this, NULL, RES_FORK, RF_NONE),                    // pid_t pid
	                            typelib_get_buffer(&param, PAGE_SIZE));                                 // struct sched_param *param

    typelib_clear_buffer(param);

    return retcode;
}


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

// Get static priority range.
// int sched_get_priority_min(int policy);
SYSFUZZ(sched_get_priority_min, __NR_sched_get_priority_min, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_sched_get_priority_min,                                               // int
                             typelib_get_integer_selection(4, SCHED_FIFO, SCHED_RR, SCHED_OTHER, SCHED_BATCH));     // int policy
}


#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"


// Return the current timespec value of tp for the specified clock
// long sys_clock_gettime (clockid_t which_clock, struct timespec *tp);
SYSFUZZ(clock_gettime, __NR_clock_gettime, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    tp;
    gint        retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_clock_gettime,                                            // long
                                typelib_get_integer(),                                                     // clockid_t which_clock,
                                typelib_get_buffer(&tp, g_random_int_range(0, 8192)));                     // struct timespec *tp

    typelib_clear_buffer(tp);

    return retcode;
}


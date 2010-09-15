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

// Get the resolution of any clock
// long sys_clock_getres (clockid_t which_clock, struct timespec *tp);
SYSFUZZ(clock_getres, __NR_clock_getres, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    tp;
    gint        retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_clock_getres,                                             // long
                                typelib_get_integer(),                                                     // clockid_t which_clock,
                                typelib_get_buffer(&tp, g_random_int_range(0, 8192)));                     // struct timespec *tp

    typelib_clear_buffer(tp);

    return retcode;
}


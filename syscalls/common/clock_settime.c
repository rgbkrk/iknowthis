#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <time.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef CLOCK_MONOTONIC_RAW
# define CLOCK_MONOTONIC_RAW 4
#endif

// Set the specified clock.
// long sys_clock_settime (clockid_t which_clock, const struct timespec *tp);
SYSFUZZ(clock_settime, __NR_clock_settime, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    tp;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_clock_settime,                                            // long
                                typelib_get_integer_selection(5, CLOCK_REALTIME,
                                                                 CLOCK_MONOTONIC,
                                                                 CLOCK_MONOTONIC_RAW,
                                                                 CLOCK_PROCESS_CPUTIME_ID,
                                                                 CLOCK_THREAD_CPUTIME_ID),                 // clockid_t which_clock
                                typelib_get_buffer(&tp, sizeof(struct timespec)));                         // const struct timespec *tp
    typelib_clear_buffer(tp);

    return retcode;
}

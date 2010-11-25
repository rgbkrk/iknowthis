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

// Get or set value of an interval timer.
SYSFUZZ(getitimer, __NR_getitimer, SYS_NONE, CLONE_FORK, 0)
{
	gpointer    c;
	gint        retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_getitimer,                             // int
	                            typelib_get_integer(),                                  // int which
	                            typelib_get_buffer(&c, g_random_int_range(0, 128)));    // struct itimerval *curr_value

    typelib_clear_buffer(c);
    return retcode;
}


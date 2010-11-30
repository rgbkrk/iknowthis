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
SYSFUZZ(setitimer, __NR_setitimer, SYS_NONE, CLONE_FORK, 0)
{
	gpointer    o;
	gpointer    n;
	glong       retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_setitimer,                             // int
	                            typelib_get_integer(),                                  // int which
	                            typelib_get_buffer(&n, g_random_int_range(0, 128)),     // const struct itimerval *new_value
	                            typelib_get_buffer(&o, g_random_int_range(0, 128)));    // struct itimerval *old_value 

    typelib_clear_buffer(o);
    typelib_clear_buffer(n);
    return retcode;
}


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

// Get / set time
SYSFUZZ(gettimeofday, __NR_gettimeofday, SYS_NONE, CLONE_DEFAULT, 0)
{
	gpointer    tv;
	gpointer    tz;
	gint        retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_gettimeofday,                          // int
	                            typelib_get_buffer(&tv, g_random_int_range(0, 128)),    // struct timeval *tv
	                            typelib_get_buffer(&tz, g_random_int_range(0, 128)));   // struct timezone *tz

    typelib_clear_buffer(tv);
    typelib_clear_buffer(tz);

    return retcode;
}


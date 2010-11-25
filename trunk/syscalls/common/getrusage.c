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

// Get resource usage.
SYSFUZZ(getrusage, __NR_getrusage, SYS_NONE, CLONE_DEFAULT, 0)
{
	gpointer    usage;
	gint        retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_getrusage,                                 // int
	                            typelib_get_integer(),                                      // int who
	                            typelib_get_buffer(&usage, g_random_int_range(0, 8192)));   // struct rusage *usage

    typelib_clear_buffer(usage);

    return retcode;
}


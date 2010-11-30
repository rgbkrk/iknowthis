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
#include <sys/time.h>
#include <sys/resource.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get/set resource limits.
// int setrlimit(int resource, const struct rlimit *rlim);
SYSFUZZ(setrlimit, __NR_setrlimit, SYS_NONE, CLONE_FORK, 0)
{
	gpointer    rlim;
	glong       retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_setrlimit,                                 // int
	                            typelib_get_integer_range(0, RLIM_NLIMITS),                 // int resource
	                            typelib_get_buffer(&rlim, PAGE_SIZE));                      // struct rlimit *rlim

    typelib_clear_buffer(rlim);
    return retcode;
}


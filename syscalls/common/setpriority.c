#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get/set program scheduling priority.
// int setpriority(int which, int who, int prio);
SYSFUZZ(setpriority, __NR_setpriority, SYS_NONE, CLONE_DEFAULT, 0)
{
	return spawn_syscall_lwp(this, NULL, __NR_setpriority,      // int
	                         typelib_get_integer_range(0, 2),   // int which
	                         typelib_get_integer(),             // int who
	                         typelib_get_integer());            // int prio
}


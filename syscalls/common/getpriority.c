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

// Get/set program scheduling priority.
SYSFUZZ(getpriority, __NR_getpriority, SYS_NONE, CLONE_DEFAULT, 0)
{
	return spawn_syscall_lwp(this, NULL, __NR_getpriority,                                                        // int
	                         typelib_get_integer_selection(3, PRIO_PROCESS, PRIO_PGRP, PRIO_USER),                // int which
	                         typelib_get_integer());                                                              // int who
}


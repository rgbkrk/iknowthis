#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Lock and unlock memory.
// int mlockall(int flags);
SYSFUZZ(mlockall, __NR_mlockall, SYS_NONE, CLONE_FORK, 0)
{
	return spawn_syscall_lwp(this, NULL, __NR_mlockall,                         // int
	                         typelib_get_integer_mask(3));                      // int flags
}


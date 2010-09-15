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

// Set real and/or effective user or group ID.
SYSFUZZ(setreuid, __NR_setreuid, SYS_NONE, CLONE_DEFAULT, 0)
{
	return spawn_syscall_lwp(this, NULL, __NR_setreuid,             // int
	                         typelib_get_integer(),                 // uid_t ruid
	                         typelib_get_integer());                // uid_t euid
}


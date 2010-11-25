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
#include "resource.h"

// Set/get process group.
// pid_t getpgid(pid_t pid);
SYSFUZZ(getpgid, __NR_getpgid, SYS_NONE, CLONE_DEFAULT, 0)
{
	return spawn_syscall_lwp(this, NULL, __NR_getpgid, typelib_get_resource(this, NULL, RES_FORK, RF_NONE)); // pid_t pid
}


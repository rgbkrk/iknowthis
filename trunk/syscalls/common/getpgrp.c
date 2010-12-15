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

// Set/get process group.
SYSFUZZ(getpgrp, __NR_getpgrp, SYS_SAFE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_getpgrp, typelib_get_resource(this, NULL, RES_FORK, RF_NONE));   // pid_t
}


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

// Get group identity.
// gid_t getgid(void);
SYSFUZZ(getgid, __NR_getgid, SYS_SAFE | SYS_BORING, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_getgid);      // gid_t
}


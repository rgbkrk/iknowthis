#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get process identification.
// pid_t getpid(void);
SYSFUZZ(getpid, __NR_getpid, SYS_BORING | SYS_SAFE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_getpid);
}

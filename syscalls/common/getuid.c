#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <linux/net.h>
#include <string.h>
#include <sys/socket.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get user identity.
// uid_t getuid(void);
SYSFUZZ(getuid, __NR_getuid, SYS_BORING, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_getuid);                            // uid_t
}


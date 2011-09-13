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

#ifndef __NR_setns
# define __NR_setns 346
#endif

// int setns(int fd, int nstype)
SYSFUZZ(setns, __NR_setns, SYS_FAIL, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_setns,                                // int
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),   // int fd
                             typelib_get_integer());                                // int nstype
}


#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <linux/reboot.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Unimplemented System Call.
SYSFUZZ(sys_setaltroot, 285, SYS_FAIL, CLONE_DEFAULT, 0)
{
    return syscall_fast(285);
}

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

// Start/stop swapping to file/device.
// int swapoff(const char *path);
SYSFUZZ(swapoff, __NR_swapoff, SYS_FAIL | SYS_BORING, CLONE_DEFAULT, 0)
{
	glong       retcode;
	gchar      *path;

    retcode = syscall_fast(__NR_swapoff,                           // int
                           typelib_get_pathname(&path));           // const char *path

    g_free(path);
    return retcode;
}


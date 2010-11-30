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

// Syscall interface to kernel nfs daemon.
// long nfsservctl(int cmd, struct nfsctl_arg *argp, union nfsctl_res *resp);
SYSFUZZ(nfsservctl, __NR_nfsservctl, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    argp;
    gpointer    resp;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_nfsservctl,                                // long
                                typelib_get_integer_range(0, 6),                            // int cmd
                                typelib_get_buffer(&argp, g_random_int_range(0, 0x1000)),   // struct nfsctl_arg *argp
                                typelib_get_buffer(&resp, g_random_int_range(0, 0x1000)));  // union nfsctl_res *resp

    typelib_clear_buffer(argp);
    typelib_clear_buffer(resp);

    return retcode;
}


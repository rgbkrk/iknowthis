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

// Switch process accounting on or off.
SYSFUZZ(acct, __NR_acct, SYS_FAIL | SYS_BORING | SYS_SAFE, CLONE_DEFAULT, 1000)
{
    gchar   *filename;
    glong    retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_acct,                      // int
                                      typelib_get_pathname(&filename));     // const char *filename

    g_free(filename);

    return retcode;
}


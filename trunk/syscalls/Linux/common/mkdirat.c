#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Create a directory.
// int mkdirat(int dirfd, const char *pathname, mode_t mode);
SYSFUZZ(mkdirat, __NR_mkdirat, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar   *pathname;
    glong    retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_mkdirat,                                           // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),                // int dirfd
                                typelib_get_pathname(&pathname),                                    // const char *pathname
                                typelib_get_integer());                                             // mode_t mode

    g_free(pathname);
    return retcode;
}


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

// Change root directory.
SYSFUZZ(chroot, __NR_chroot, SYS_FAIL, CLONE_DEFAULT, 0)
{
	gchar   *path;
    gint     retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_chroot,                                    // int
                                typelib_get_pathname(&path));                               // const char *path

    g_free(path);

    return retcode;
}


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


// Make a new name for a file.
SYSFUZZ(symlink, __NR_symlink, SYS_NONE, CLONE_DEFAULT, 0)
{
	gchar   *oldpath;
	gchar   *newpath;
	glong    retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_symlink,                                       // int
	                            typelib_get_pathname(&oldpath),                                 // const char *oldpath
	                            typelib_get_pathname(&newpath));                                // const char *newpath

    g_free(oldpath);
    g_free(newpath);

    return retcode;
}

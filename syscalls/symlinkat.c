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
// int symlinkat(const char *oldpath, int newdirfd, const char *newpath);
SYSFUZZ(symlinkat, __NR_symlinkat, SYS_NONE, CLONE_DEFAULT, 0)
{
	gchar   *oldpath;
	gchar   *newpath;
	gint     retcode;
	gint     fd;

    // Relative to the current working directory.
	fd = g_random_boolean()
	    ? typelib_fd_get(this)
        : AT_FDCWD;

	retcode = spawn_syscall_lwp(this, NULL, __NR_symlinkat,                                     // int
	                            typelib_get_pathname(&oldpath),                                 // const char *oldpath
                                fd,                                                             // int newdirfd
	                            typelib_get_pathname(&newpath));                                // const char *newpath

    g_free(oldpath);
    g_free(newpath);

    return retcode;
}


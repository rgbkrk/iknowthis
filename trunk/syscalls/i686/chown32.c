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

// Change ownership of a file.
SYSFUZZ(chown32, __NR_chown32, SYS_NONE, CLONE_DEFAULT, 0)
{
	gchar   *path;
	gint     retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_chown32,                               // int
	                            typelib_get_pathname(&path),                            // const char *path
	                            typelib_get_integer(),                                  // uid_t owner
	                            typelib_get_integer());                                 // gid_t group

    g_free(path);
    return retcode;   
}


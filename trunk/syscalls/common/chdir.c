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

// Change working directory.
SYSFUZZ(chdir, __NR_chdir, SYS_NONE, CLONE_DEFAULT, 0)
{
	gchar *pathname;
	gint   retcode;

	// Execute systemcall.
	retcode = spawn_syscall_lwp(this, NULL, __NR_chdir,               // int
                                typelib_get_pathname(&pathname));     // const char *pathname

    g_free(pathname);

    return retcode;
}

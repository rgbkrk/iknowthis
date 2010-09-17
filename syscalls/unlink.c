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

// Delete a name and possibly the file it refers to.
SYSFUZZ(unlink, __NR_unlink, SYS_NONE, CLONE_DEFAULT, 0)
{
	gchar *pathname;
	gint   retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_unlink,              // int
                                typelib_get_pathname(&pathname));     // const char *pathname

    g_free(pathname);

    return retcode;
}

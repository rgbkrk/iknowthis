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


// Create a special or ordinary file.
SYSFUZZ(mknodat, __NR_mknodat, SYS_NONE, CLONE_DEFAULT, 0)
{
	gchar *pathname;
	gint   retcode;

	// Execute systemcall.
	retcode = spawn_syscall_lwp(this, NULL, __NR_mknodat,             // int
                                typelib_fd_get(this),                 // int dirfd
	                            typelib_get_pathname(&pathname),      // const char *pathname
	                            typelib_get_integer(),                // mode_t mode
       	                        typelib_get_integer());               // dev_t dev
    
    g_free(pathname);

    return retcode;
}


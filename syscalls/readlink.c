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

// Read value of a symbolic link.
SYSFUZZ(readlink, __NR_readlink, SYS_NONE, CLONE_DEFAULT, 0)
{
	gchar       *pathname;
	gpointer    buf;
	gint        retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_readlink,                              // ssize_t
	                            typelib_get_pathname(&pathname),                        // const char *path
	                            typelib_get_buffer(&buf, g_random_int_range(0, 1024)),  // char *buf
	                            typelib_get_integer());                                 // size_t bufsiz

    g_free(pathname);
    typelib_clear_buffer(buf);

    return retcode;
}


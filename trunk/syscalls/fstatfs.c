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

// Get file system statistics.
SYSFUZZ(fstatfs, __NR_fstatfs, SYS_NONE, CLONE_DEFAULT, 0)
{
	gpointer     buf;
	gint         retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_fstatfs,                                   // int
	                            typelib_fd_get(this),                                       // int fd
	                            typelib_get_buffer(&buf, g_random_int_range(0, 0x1000)));   // struct statfs *buf

    typelib_clear_buffer(buf);

    return retcode;
}


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

// Transfer data between file descriptors.
// ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
SYSFUZZ(sendfile, __NR_sendfile, SYS_NONE, CLONE_DEFAULT, 1000)
{
	gpointer    offset;
	gint        retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_sendfile,                              // ssize_t
	                            typelib_fd_get(this),                                   // int out_fd
	                            typelib_fd_get(this),                                   // int int_fd
	                            typelib_get_buffer(&offset, g_random_int_range(0, 8)),  // off_t *offset
	                            typelib_get_integer());                                 // size_t count
    
    typelib_clear_buffer(offset);

    return retcode;
}


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

// Read from a file descriptor.
SYSFUZZ(pwritev, __NR_pwritev, SYS_NONE, CLONE_DEFAULT, 1000)
{
	gsize       size;
	gint        retcode;
	gpointer    buffer;
	
	// Choose how big the buffer should be for input.
	size = g_random_int_range(0, 0x10000);

    // Execute systemcall.
    // XXX FIXME BROKEN
    retcode = spawn_syscall_lwp(this, NULL, __NR_pwritev,               // ssize_t
                                typelib_fd_get(this),                   // int fd
                                typelib_get_buffer(&buffer, size),      // void *buf
                                size,                                   // size_t count
                                typelib_get_integer());                 // off_t offset

    // Clean up.
    typelib_clear_buffer(buffer);

    return retcode;
}

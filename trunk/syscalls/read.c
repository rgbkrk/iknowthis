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
SYSFUZZ(read, __NR_read, SYS_NONE, CLONE_DEFAULT, 1000)
{
	gint        retcode;
	gpointer    buffer;
	
	if (1) {
        // Execute systemcall.
        retcode = spawn_syscall_lwp(this, NULL, __NR_read,                  // ssize_t
                                    typelib_fd_get(this),                   // int fd
                                    typelib_get_buffer(&buffer, PAGE_SIZE), // void *buf
                                    typelib_get_integer_range(0, PAGE_SIZE));                 // size_t count

        // Clean up.
        typelib_clear_buffer(buffer);
    } else {
        // Execute systemcall.
        retcode = spawn_syscall_lwp(this, NULL, __NR_read,                   // ssize_t
                                    typelib_fd_get(this),                    // int fd
                                    typelib_get_vma(this, NULL, NULL),       // void *buf
                                    typelib_get_integer_range(0, PAGE_SIZE));// size_t count
    }

    return retcode;
}

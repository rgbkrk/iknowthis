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
// ssize_t read(int fd, void *buf, size_t count);
SYSFUZZ(read, __NR_read, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gint        retcode;
    gpointer    buffer;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_read,                                                  // ssize_t
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),                    // int fd
                                typelib_get_buffer(&buffer, PAGE_SIZE),                                 // void *buf
                                typelib_get_integer_range(0, PAGE_SIZE));                               // size_t count

    // Clean up.
    typelib_clear_buffer(buffer);

    return retcode;
}

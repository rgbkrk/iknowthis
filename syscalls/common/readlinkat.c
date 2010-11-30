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
// int readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);
SYSFUZZ(readlinkat, __NR_readlinkat, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar       *pathname;
    gpointer    buf;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_readlinkat,                            // ssize_t
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),    // int dirfd
                                typelib_get_pathname(&pathname),                        // const char *path
                                typelib_get_buffer(&buf, PAGE_SIZE),                    // char *buf
                                typelib_get_integer_range(0, PAGE_SIZE));               // size_t bufsiz

    g_free(pathname);
    typelib_clear_buffer(buf);

    return retcode;
}


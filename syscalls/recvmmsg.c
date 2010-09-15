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

// Recieve multiple messages.
// ssize_t recvmmsg(int socket, struct mmsghdr *mmsg, int vlen, int flags);
SYSFUZZ(recvmmsg, __NR_recvmmsg, SYS_NONE, CLONE_DEFAULT, 1000)
{
	gint        retcode;
	gpointer    mmsg;
	
    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_recvmmsg,              // ssize_t
                                typelib_fd_get(this),                   // int fd
                                typelib_get_buffer(&mmsg, PAGE_SIZE),   // void *buf
                                typelib_get_integer());                 // size_t count

    // Clean up.
    typelib_clear_buffer(mmsg);

    return retcode;
}


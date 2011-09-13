#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <linux/net.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef __NR_sendmmsg
# define __NR_sendmmsg 345
#endif

// Send a message on a socket.
// int sendmmsg(int fd, struct mmsghdr *mmsg, unsigned int vlen, unsigned int flags);
SYSFUZZ(sendmmsg, __NR_sendmmsg, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    msg;

    retcode = spawn_syscall_lwp(this, NULL, __NR_sendmmsg,                                  // int
                                      typelib_get_resource(this, NULL, RES_FILE, RF_NONE),  // int sockfd
                                      typelib_get_buffer(&msg, PAGE_SIZE),                  // struct mmsghdr *msg
                                      typelib_get_integer_range(0, 8),                      // int vlen
                                      typelib_get_integer());                               // int flags

    typelib_clear_buffer(msg);
    return retcode;
}

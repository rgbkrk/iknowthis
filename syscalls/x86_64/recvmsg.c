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

// Receive a message from a socket.
// ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
SYSFUZZ(recvmsg, __NR_recvmsg, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    msg;

    retcode = spawn_syscall_lwp(this, NULL, __NR_recvmsg,                                   // ssize_t
                                      typelib_get_resource(this, NULL, RES_FILE, RF_NONE),  // int sockfd
                                      typelib_get_buffer(&msg, PAGE_SIZE),                  // const struct msghdr *msg
                                      typelib_get_integer());                               // int flags

    typelib_clear_buffer(msg);
    return retcode;
}

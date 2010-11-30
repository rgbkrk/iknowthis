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

// Initiate a connection on a socket.
// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
SYSFUZZ(connect, __NR_connect, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    addr;

    retcode = syscall_fast(__NR_connect,                                                // int
                           typelib_get_resource(this, NULL, RES_FILE, RF_NONE),         // int sockfd
                           typelib_get_integer_range(0, 64),                            // const struct sockaddr *addr
                           typelib_get_buffer(&addr, PAGE_SIZE));                       // socklen_t addrlen

    typelib_clear_buffer(addr);
    return retcode;
}


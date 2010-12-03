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

// Callback for typelib_add_resource().
static gboolean destroy_open_file(guintptr fd)
{
    return syscall(__NR_close, fd) != -1;
}

// Accept a connection on a socket.
// int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
SYSFUZZ(accept, __NR_accept, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    glong       fd;
    gpointer    addr;
    socklen_t   addrlen;

    addrlen = typelib_get_integer_selection(1, sizeof(struct sockaddr));

    retcode = spawn_syscall_lwp(this, &fd, __NR_accept,
                                      typelib_get_resource(this, NULL, RES_FILE, RF_NONE),  // int sockfd
                                      typelib_get_buffer(&addr, sizeof(struct sockaddr)),   // struct sockaddr *addr
                                      &addrlen);                                            // socklen_t *addrlen;


    // Check for new socket.
    if (retcode == ESUCCESS) {
        // Seems unlikely this would happen by chance.
        g_debug("unexpected: retrieved a new socket descriptor %ld from accept", fd);

        typelib_add_resource(this, fd, RES_FILE, RF_NONE, destroy_open_file);
    }

    typelib_clear_buffer(addr);

    return retcode;
}


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

// Control device.
// int ioctl(int d, int request, ...);
SYSFUZZ(ioctl, __NR_ioctl, SYS_NONE, CLONE_DEFAULT, 0)
{
    guint        req;
    guint        arg;
    gint         fd;
    gpointer     buffer;
    glong        retcode;

    // Choose a random ioctl request and argument.
    req = typelib_get_integer();
    arg = typelib_get_integer();

    // Choose the device.
    fd  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);

    // Execute a probe ioctl to see if the final parameter is an address.
    retcode = syscall_fast(__NR_ioctl, fd, req, ~0);

    // The probe failed, see if I can determine why from errno.
    switch (retcode) {
        case EFAULT:     // Bad address
            // It was expecting an address, let's give him one.
            retcode = syscall_fast(__NR_ioctl, fd, req, typelib_get_buffer(&buffer, PAGE_SIZE));

            // Clean up
            typelib_clear_buffer(buffer);
            break;
        default:
            g_debug("unexpected errno set by ioctl, %ld (%s)", retcode, custom_strerror_wrapper(retcode));
            // Fallthrough
        case ESUCCESS:   // Success
        case ENOTTY:     // Inappropriate ioctl for device
        case EINVAL:     // Invalid argument
        case EPERM:      // Permission denied
        case ENXIO:      // No such device
        case EOPNOTSUPP: // Operation not supported on transport endpoint
        case EIO:        // Input/Output Error
        case EACCES:     // Permission Denied
        case ENOSYS:     // Function not implemented (rfkill?)
        case EBADF:      // Bad file descriptor
        case EBADFD:     // File descriptor in bad state
        case ENOTCONN:   // Transport endpoint is not connected
        case ETIMEOUT:
            // Doesn't look like an address was expected, just rerun with a random parameter.
            retcode = syscall_fast(__NR_ioctl, fd, req, arg);
            break;
    }

    return retcode;
}

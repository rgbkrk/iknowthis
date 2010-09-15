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
SYSFUZZ(ioctl, __NR_ioctl, SYS_NONE, CLONE_DEFAULT, 0)
{
	guint        req;
	guint        arg;
	gint         fd;
	gint         retcode;
    static gint  r_mask;

    // Choose a random ioctl request and argument.
    req = typelib_get_integer_mask(r_mask) | (1 << g_random_int_range(0, 32));
    arg = typelib_get_integer();

    // Choose the device.
    fd  = typelib_fd_get(this);    

    // Execute a probe ioctl.
    retcode = spawn_syscall_lwp(this, NULL, __NR_ioctl,                                         // int
                                fd,                                                             // int fd
                                req,                                                            // int request
                                ~0);                                                            // ...

    // Remember that this mask is valid.
    if (retcode != EINVAL)
        r_mask |= req;

    // If that succeeded, it must ignore the arg parameter, or all flags are
    // valid (seems unlikely).
    if (retcode == ESUCCESS) {
    	// Re-run with random combination of flags.
    	return spawn_syscall_lwp(this, NULL, __NR_ioctl,                                        // int
    	                         fd,                                                            // int fd
    	                         req,                                                           // int request
    	                         arg);                                                          // ...
    }

    // Call expected an address, so give it one
    if (retcode == EFAULT) {
    	gpointer buffer;

    	retcode = spawn_syscall_lwp(this, NULL, __NR_ioctl,                                     // int
    	                            fd,                                                         // int fd
    	                            req,                                                        // int request
    	                            typelib_get_buffer(&buffer, g_random_int_range(0, 8192)));  // ...
        
        typelib_clear_buffer(buffer);
        return retcode;
    }

    // The probe failed, see if I can determine why from errno.
    switch (retcode) {
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
    	    break;
        default:
            g_debug("unexpecter errno set by ioctl, %d (%s)", retcode, g_strerror(retcode));
            break;
    }

    return retcode;
}

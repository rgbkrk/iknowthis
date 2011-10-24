#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Synchronize a file with a memory map.
// int msync(void *addr, size_t length, int flags);
SYSFUZZ(msync, __NR_msync, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    guintptr    address;
    gsize       size;

    typelib_get_vma(this, &address, &size);

    retcode = spawn_syscall_lwp(this, NULL, __NR_msync,                                         // int
                                address,                                                        // void *addr
                                size,                                                           // size_t len
                                typelib_get_integer_mask(MS_ASYNC | MS_INVALIDATE | MS_SYNC));  // int flags

    return retcode;
}


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


// Map or unmap files or devices into memory.
// int munmap(void *addr, size_t length);
SYSFUZZ(munmap, __NR_munmap, SYS_DISABLED, CLONE_DEFAULT, 0)
{
	gint        retcode;
	guintptr    address;
	gsize       size;

    typelib_get_vma(this, &address, &size);

	retcode = spawn_syscall_lwp(this, NULL, __NR_munmap,                        // int
	                            address,                                        // void *addr
	                            size);

    if (retcode == ESUCCESS) {
    	typelib_vma_stale(this, address);
    }

    return retcode;
}


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

// Lock and unlock memory.
// int mlock(const void *addr, size_t len);
SYSFUZZ(mlock, __NR_mlock, SYS_NONE, CLONE_DEFAULT, 0)
{
	glong       retcode;
	guintptr    address;
	gsize       size;

	typelib_get_vma(this, &address, &size);

	retcode = spawn_syscall_lwp(this, NULL, __NR_mlock,                         // int
	                            address,                                        // void *addr
	                            size);                                          // size_t len

    return retcode;
}


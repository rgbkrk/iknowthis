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

// Set protection on a region of memory.
// int mprotect(const void *addr, size_t len, int prot);
SYSFUZZ(mprotect, __NR_mprotect, SYS_NONE, CLONE_DEFAULT, 0)
{
	gint        retcode;
	guintptr    address;
	gsize       size;

	typelib_get_vma(this, &address, &size);

	retcode = spawn_syscall_lwp(this, NULL, __NR_mprotect,                      // int
	                            address,                                        // void *addr
	                            size,                                           // size_t len
	                            typelib_get_integer_mask(PROT_READ
                                                       | PROT_WRITE
                                                       | PROT_EXEC
                                                       | PROT_GROWSDOWN
                                                       | PROT_GROWSUP));        // int prot


    return retcode;
}


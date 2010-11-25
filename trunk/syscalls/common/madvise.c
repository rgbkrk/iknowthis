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

#ifndef MADV_MERGEABLE
# define MADV_MERGEABLE 12
#endif
#ifndef MADV_UNMERGEABLE
# define MADV_UNMERGEABLE 13
#endif

// Give advice about use of memory.
// int madvise(void *start, size_t length, int advice);
SYSFUZZ(madvise, __NR_madvise, SYS_NONE, CLONE_DEFAULT, 0)
{
    guintptr    address;
    gsize       size;

    typelib_get_vma(this, &address, &size);

    return spawn_syscall_lwp(this, NULL, __NR_madvise,                          // int
                             address,                                           // void *start
                             size,                                              // size_t length
                             typelib_get_integer_selection(10, MADV_DOFORK,
                                                               MADV_DONTFORK,
                                                               MADV_NORMAL,
                                                               MADV_SEQUENTIAL,
                                                               MADV_RANDOM,
                                                               MADV_REMOVE,
                                                               MADV_WILLNEED,
                                                               MADV_DONTNEED,
                                                               MADV_MERGEABLE,
                                                               MADV_UNMERGEABLE));  // int advice

    // Selection is from madvise_behavior_valid(), madvise.c
}


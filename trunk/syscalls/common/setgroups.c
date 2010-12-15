#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get/set list of supplementary group IDs.
// int setgroups(size_t size, const gid_t *list);
SYSFUZZ(setgroups, __NR_setgroups, SYS_FAIL, CLONE_DEFAULT, 0)
{
    gpointer    list;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_setgroups,                                 // int
                                typelib_get_integer(),                                      // int size
                                typelib_get_buffer(&list, PAGE_SIZE));                      // gid_t list[]

    typelib_clear_buffer(list);

    return retcode;
}


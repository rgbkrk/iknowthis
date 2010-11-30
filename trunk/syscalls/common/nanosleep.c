#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// High-resolution sleep.
// int nanosleep(const struct timespec *req, struct timespec *rem);
SYSFUZZ(nanosleep, __NR_nanosleep, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer    req;
    gpointer    rem;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_nanosleep,
                                typelib_get_buffer(&req, g_random_int_range(0, PAGE_SIZE)),   // const struct timespec *req
                                typelib_get_buffer(&rem, g_random_int_range(0, PAGE_SIZE)));  // struct timespec *rem

    typelib_clear_buffer(req);
    typelib_clear_buffer(rem);

    return retcode;
}


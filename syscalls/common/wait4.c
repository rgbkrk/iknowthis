#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"
#include "resource.h"

// Wait for process to change state, BSD style.
// pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage);
SYSFUZZ(wait4, __NR_wait4, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer     status;
    gpointer     rusage;
    gint         retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_wait4,                                                                 // pid_t
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),                                    // pid_t pid
                                typelib_get_buffer(&status, PAGE_SIZE),                                                 // int *status
                                typelib_get_integer_mask(WNOHANG|WUNTRACED|WCONTINUED|__WNOTHREAD|__WCLONE|__WALL),     // int options
                                typelib_get_buffer(&rusage, PAGE_SIZE));                                                // struct rusage *rusage

    // Mask is from initial check in sys_wait4() (exit.c, 2.6.25.3).
    typelib_clear_buffer(status);
    typelib_clear_buffer(rusage);
    return retcode;
}


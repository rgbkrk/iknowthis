#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Examine and change blocked signals.
// long sys_rt_sigprocmask (int how, sigset_t *set, sigset_t *oset,
//                          size_t sigsetsize);

SYSFUZZ(rt_sigprocmask, __NR_rt_sigprocmask, SYS_NONE, CLONE_FORK, 0)
{
	gpointer    set;
    gpointer    oset;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_rt_sigprocmask,
                                typelib_get_integer_selection(3, SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK),  // int how
                                typelib_get_buffer(&set, g_random_int_range(0, 32)),                    // sigset_t *set
                                typelib_get_buffer(&oset, g_random_int_range(0, 32)),                   // sigset_t *oset
                                typelib_get_integer_selection(1, sizeof(sigset_t)));                    // size_t sigsetsize

    typelib_clear_buffer(set);
    typelib_clear_buffer(oset);
    return retcode;
}


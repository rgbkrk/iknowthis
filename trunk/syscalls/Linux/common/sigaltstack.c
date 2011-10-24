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

// Set and/or get signal stack context.
// int sigaltstack(const stack_t *ss, stack_t *oss);
SYSFUZZ(sigaltstack, __NR_sigaltstack, SYS_NONE, CLONE_FORK, 0)
{
    gpointer    ss;
    gpointer    oss;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_sigaltstack,                           // int
                                typelib_get_buffer(&ss, sizeof(stack_t)),               // const stack_t *ss
                                typelib_get_buffer(&oss, sizeof(stack_t)));             // stack_t *oss

    typelib_clear_buffer(ss);
    typelib_clear_buffer(oss);

    return retcode;
}


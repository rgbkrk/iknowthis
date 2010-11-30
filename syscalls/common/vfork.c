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

// Create a child process and block parent.
// pid_t fork(void);
// XXX: not working
SYSFUZZ(vfork, __NR_vfork, SYS_DISABLED, CLONE_DEFAULT, 0)
{
	glong   retcode;
	pid_t   pid;

    // I think the lwp syscall code may not handle this well, luckily vfork() is
    // simple enough that I can handle it here.
	retcode = syscall_fast_ret(&pid, __NR_vfork);

    // Determine what happened.
    switch (pid) {
        // In the child, don't do anything.
    	case  0: syscall(__NR_exit, 0);
                 g_assert_not_reached();
        // Fork failed, just return error.
    	case -1: return retcode;
    }
    
    g_assert_cmpint(retcode, ==, 0);
    
    waitpid(pid, NULL, __WALL);

    return retcode;
}


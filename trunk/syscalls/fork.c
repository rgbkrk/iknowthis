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
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/mman.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"
#include "resource.h"

// Callback for typelib_add_resource().
static gboolean destroy_forked_process(guintptr pid)
{
	g_assert_cmpuint(pid, >, 1);
    syscall(__NR_kill, pid, SIGKILL);
    syscall(__NR_waitpid, pid, NULL, __WALL);

    return true;
}

// Create a child process.
// pid_t fork(void);
SYSFUZZ(fork, __NR_fork, SYS_NONE, CLONE_DEFAULT, 0)
{
	gint            retcode;
	pid_t           pid = -1;

    // I think the lwp syscall code may not handle this well, luckily fork() is
    // simple enough that I can handle it here.
	retcode = syscall_fast_ret(&pid, __NR_fork);

    // Determine what happened.
    switch (pid) {
    	case  0: // In the child process, increment nesting depth.
    	         process_nesting_depth++;

    	         // Learn about myself.
    	         typelib_add_resource(this, syscall(__NR_getpid), RES_FORK, RF_NONE, destroy_forked_process);

    	         // Possible learn about parent if it's not the master.
    	         if (process_nesting_depth > 1) {
        	        typelib_add_resource(this, syscall(__NR_getppid), RES_FORK, RF_NONE, destroy_forked_process);
                 }

                 // Make sure this wouldnt put us over process quota.
                 if (increment_process_count() > MAX_PROCESS_NUM) {
                 	 // Terminate self.
                 	 syscall(__NR_exit, 0);

                 	 // Shouldn't continue.
                 	 g_assert_not_reached();
                 }

    	         // Mangle prng state.
    	         g_random_set_seed(time(0) ^ getpid());

                 // Continue fuzzing.
                 break;

        // Fork failed, just return error.
    	case -1: break;

        // Parent process, add the child.
    	default: typelib_add_resource(this, pid, RES_FORK, RF_NONE, destroy_forked_process);
    	         break;
    }

    return retcode;
}

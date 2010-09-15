#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

static gpointer fuzzerstack;
static gpointer watchdogstack;

static void __constructor init_thread_stacks(void)
{
	fuzzerstack   = mmap(NULL,
	                     getpagesize() * 8,
	                     PROT_READ | PROT_WRITE,
	                     MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN,
	                     -1,
	                     0);
	watchdogstack = mmap(NULL,
	                     getpagesize() * 8,
	                     PROT_READ | PROT_WRITE,
	                     MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN,
	                     -1,
	                     0);

	g_assert(fuzzerstack != MAP_FAILED);
	g_assert(watchdogstack != MAP_FAILED);

    fuzzerstack     += getpagesize() * 4;
    watchdogstack   += getpagesize() * 4;

	return;
}

// Thread used to monitor for fuzzer for timeout.
static gint watchdog_thread_func(gpointer this)
{
	syscall_fuzzer_t *fuzzer = this;
	struct timespec request = {
		.tv_sec     = fuzzer->timeout ? 0 : 32,                   // Default timeout
		.tv_nsec    = fuzzer->timeout * 1000,                     // Microseconds.
    };

    // Convert timeout to nanoseconds, and use nanosleep to delay.
	if (nanosleep(&request, NULL) != 0) {
		g_warning("watchdog thread failed to sleep for the requested interval, %s", g_strerror(errno));
		return 1;
    }

	//g_message("watchdog thread terminating %d after %u useconds timeout",
	//          watchdog->pid,
	//          watchdog->timeout);

    if (fuzzer->timeout == 0) {
    	g_message("fuzzer %s reached the default cap on execution time", fuzzer->name);
    }

    // I'm still here, so kill the thread.
	if (kill(fuzzer->pid, SIGKILL) != 0) {
		// This is normal, just a small race condition.
		g_assert_cmpint(errno, ==, ESRCH);

		//g_message("watchdog thread failed to terminate hung process %d, %s",
		//          fuzzer->pid,
		//          g_strerror(errno));
    }

    return 0;
}

// Execute a systemcall.
gint lwp_systemcall_routine(gpointer context)
{
    gint **status = context;
    gint   result;

    // Initialise, in case I'm killed.
    **status = -ESUCCESS;

    __asm__ __volatile__(
        "push       %%ebp                       \n" // Save ebp
        "mov        %[context],  %%eax          \n" // Find address of parameters.
        "mov        0x08(%%eax), %%ebx          \n" // arg0
        "mov        0x0c(%%eax), %%ecx          \n" // arg1
        "mov        0x10(%%eax), %%edx          \n" // arg2
        "mov        0x14(%%eax), %%esi          \n" // arg3
        "mov        0x18(%%eax), %%edi          \n" // arg4
        "mov        0x1c(%%eax), %%ebp          \n" // arg5
        "mov        0x04(%%eax), %%eax          \n" // Systemcall number.
        "xor        $0xDEADBEEF, %%esp          \n" // Obscure esp to catch kernel trusting it.
        "int        $0x80                       \n" // System call.
        "xor        $0xDEADBEEF, %%esp          \n" // Restore esp.
        "pop        %%ebp                       \n" // Restore ebp
            :          "=a"  (result)
            : [context] "m"  (context)
            : "%ebx", "%ecx", "%edx", "%esi", "%edi"
    );

    // Save result.
    **status = result;

    return 0;
}

gint spawn_syscall_lwp(syscall_fuzzer_t *this, gint *status, gint sysno, ...)
{
	gint   watchdogpid, childpid;
	gint   watchdogstatus, childstatus;
	gint   watchdogret;
	gint   retcode;

    // Quick sanity check.
    g_assert_cmpint(this->number, ==, sysno);

    // If caller doesn't want the return code, I'll save it.
    status = status ? status : &retcode;

    // If nothing can go wrong with this call, don't waste time
    // with clones.
    if (this->flags & SYS_SAFE) {
    	if (lwp_systemcall_routine(&status) != 0) {
    		g_warning("fuzzer %s was marked safe, but something weird happened", this->name);
        }
        
        // Calculate return code.
    	return (unsigned)(*status) >= 0xfffff001
    	        ? - *status
    	        : 0;
    }

    // Spawn the fuzzer.
	if ((this->pid = clone(lwp_systemcall_routine, fuzzerstack, this->shared, &status)) == -1) {
		g_critical("failed to spawn lwp for fuzzer %s, %s", this->name, g_strerror(errno));
    }

    // Spawn watchdog.
    if ((watchdogpid = clone(watchdog_thread_func, watchdogstack, CLONE_DEFAULT, this)) == -1) {
    	g_critical("failed to spawn watchdog thread for %s, %s", this->name, g_strerror(errno));

    	// Kill it to prevent hangs.
    	kill(this->pid, SIGKILL);
    }
    
    // And now we play the waiting game.
    childpid = waitpid(this->pid, &childstatus, __WALL);

    // Child has returned, (possibly) kill watchdog. Note that it might already
    // be dead, if the child timedout.
    kill(watchdogpid, SIGKILL);

    // Wait for the watchdog to return.
    watchdogret = waitpid(watchdogpid, &watchdogstatus, __WALL);

    // Special case execve which is weird.
    if (sysno != __NR_execve) {
        // Check that worked.
        if (childpid == -1 || watchdogret == -1) {
        	g_critical("failed to wait for one of my lwps for %s, %s", this->name, g_strerror(errno));
        }

        g_assert_cmpint(childpid, ==, this->pid);
        g_assert_cmpint(watchdogret, ==, watchdogpid);
    }
    
    // Child completed before timeout.
    if (WIFEXITED(childstatus)) {
        return (unsigned)(*status) >= 0xfffff001
                    ? - *status
                    : 0;
    }

    // Child crashed.
    if (WIFSIGNALED(childstatus) && WTERMSIG(childstatus) != SIGKILL)
    	return EKILLED;

    // Watchdog killed just after killing fuzzer.
    if (WIFSIGNALED(childstatus) && WTERMSIG(childstatus) == SIGKILL)
    	return ETIMEOUT;

    if (WIFEXITED(childstatus)) {
    	g_debug("fuzzer %s child exited with %d", this->name, WEXITSTATUS(childstatus));
    }

    if (WIFSIGNALED(childstatus)) {
    	g_debug("fuzzer %s child terminated with %d", this->name, WTERMSIG(childstatus));
    }

    if (WIFEXITED(watchdogstatus)) {
    	g_debug("watchdog exited with %d", WEXITSTATUS(childstatus));
    }

    if (WIFSIGNALED(watchdogstatus)) {
    	g_debug("watchdog terminated with %d", WTERMSIG(childstatus));
    }

    // FIXME: What else could happen?
    g_assert_not_reached();
}

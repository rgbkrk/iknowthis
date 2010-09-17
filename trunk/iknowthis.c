#include <stdbool.h>
#include <search.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <sched.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

syscall_fuzzer_t   system_call_fuzzers[MAX_SYSCALL_NUM]; // Fuzzer definitions for each system call.
guint              total_registered_fuzzers;             // Total number of registered fuzzers.
guint              total_disabled_fuzzers;               // Number of fuzzers that have been disabled.
guint              process_nesting_depth;                // Nested process depth.

int main(int argc, char **argv)
{
    GTimer         *timer       = NULL;
    gint            returncode  = 0;
    guint           total       = 0;

    // Print some stats
    g_message("welcome to iknowthis, a linux system call fuzzer, pid %5u", getpid());
    g_message("--------------------------------- http://goo.gl/is02 ------");
    g_message("%u known system calls, %u fuzzers registered, of which %u are disabled",
              MAX_SYSCALL_NUM,
              total_registered_fuzzers,
              total_disabled_fuzzers);

    // Used for timing fuzzers.
    timer = g_timer_new();

    // Spam pages with a secret value to look for leaks.
    //create_dirty_pages();

    // Setup some default signals.
    signal(SIGPIPE, SIG_IGN);
    signal(SIGXFSZ, SIG_IGN);

    while (true) {
        // Select a random fuzzer.
        syscall_fuzzer_t *fuzzer = &system_call_fuzzers[
            g_random_int_range(0, MAX_SYSCALL_NUM)
        ];

        // Skip if undefined or disabled.
        if (fuzzer->callback == NULL || fuzzer->flags & SYS_DISABLED) {
            continue;
        }

        // Count how many fuzzers executed.
        total++;

        //g_message("fuzzer %s selected, %u total executions", fuzzer->name, fuzzer->total);

        // Execute the fuzzer, timing the operation.
        g_timer_start(timer);

        // Fuzzers are executed in their own lwp, in order to isolate us from damage.
        returncode = fuzzer->callback(fuzzer);

        // Terminate timer.
        g_timer_stop(timer);

        // Keep a running average of speed for this fuzzer.
        fuzzer->average = ((fuzzer->average * fuzzer->total) + g_timer_elapsed(timer, NULL))
                            / (fuzzer->total + 1);

        // And keep track of executions.
        fuzzer->total++;

        //g_message("fuzzer %s executed in %f seconds, returned %d (%s)",
        //          fuzzer->name,
        //          g_timer_elapsed(timer, NULL),
        //          returncode,
        //          g_strerror(returncode));

        // Should I ignore this?
        if (fuzzer->flags & SYS_VOID) {
            returncode = ESUCCESS;
        }

        // Is this supposed to fail?
        if (fuzzer->flags & SYS_FAIL && returncode == ESUCCESS) {
            g_critical("fuzzer %s unexpectedly succeeded", fuzzer->name);
            abort();
        }

        // Record error distribution to spot poor coverage.
        if (returncode != ESUCCESS) {
            error_record_t *error, key = { returncode, 0 };

            // Make sure this looks sane.
            g_assert_cmpuint(fuzzer->numerrors, <, MAX_ERROR_CODES);
            g_assert_cmpuint(fuzzer->failures, <, fuzzer->total);

            // Define compare callback for lsearch().
            gint compare_error(gconstpointer a, gconstpointer b)
            {
                return ((const error_record_t *)(a))->error 
                    -  ((const error_record_t *)(b))->error;
            }

            // XXX: if this is a bottleneck, qsort on insertion and use bsearch().
            error = lsearch(&key,                   // key
                            fuzzer->errors,         // base
                            &fuzzer->numerrors,     // num
                            sizeof key,             // size
                            compare_error);         // compare

            // I don't expect this routine to fail.
            g_assert(error);

            // Record this error.
            fuzzer->failures++;

            // Check if it's new.
            if (error->count++ == 0) {
                //g_message("fuzzer %s returned a new error, %s (%u executions, %u failures).",
                //          fuzzer->name,
                //          g_strerror(error->error),
                //          fuzzer->total,
                //          fuzzer->failures);
            }

            //if (fuzzer->total > 1024) {
            //  if (fuzzer->failures == fuzzer->total && fuzzer->numerrors == 1) {
            //      g_message("disabled boring fuzzer %s", fuzzer->name);
            //      fuzzer->flags |= SYS_DISABLED;
            //    }
            //}
        }
    }

    g_timer_destroy(timer);

    return 0;
}


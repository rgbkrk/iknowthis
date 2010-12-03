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

// We need to cap the number of processes created to avoid fork bombing the
// system. The obvious solution is setrlimit(RLIM_NPROC), but this is uid wide
// and will intefere with the operation of the rest of the system. LWPs also
// count against this limit, which would interfere with fuzzing.
//
// We need a kernel supported listener count, that we can check. I considered
// sockets, files, semaphores, but I think the most reliable is shmid attach
// counts.
//
// Note that zombies do _not_ count against this limit. Zombies are cleaned up
// by the resource management code when they are evicted from the list.

// The shmid for this process.
static gint     shmid;

void __constructor create_process_shmid(void)
{
    struct shmid_ds shmds;

    // I should only be called once.
    g_assert_cmpint(shmid, ==, 0);
    g_assert(system_call_fuzzers == NULL);

    // Create a shmid, used to track process creations.
    // ftok() does a stat(), and uses the inode number combined with the
    // proj_id, so I'll use the process id.
    if ((shmid = shmget(ftok("/proc/self/exe", getpid()), PAGE_SIZE, IPC_CREAT | 0666)) == -1) {
        // I cannot safely continue, or I might take the system down.
        g_critical("unable to create a shared segment id to track processes, %s", g_strerror(errno));
        abort();
    }

    // Attach to this segment.
    if (shmat(shmid, NULL, 0) == MAP_FAILED) {
        // This is probably not good.
        g_critical("there was an error attaching to shmid %#x, %s.", shmid, g_strerror(errno));
        abort();
    }

    // Mark the shmid for deletion so that it's destroyed on exit.
    // This isn't really essential, it just prevents leaving a mess behind.
    shmctl(shmid, IPC_RMID, NULL);

    // Quick sanity check to ensure the nattach count is working.
    g_assert_cmpint(shmctl(shmid, IPC_STAT, &shmds), !=, -1);
    g_assert_cmpint(shmds.shm_nattch, ==, 1);
    return;
}

// Increment the spawned process count for this fuzzing session, and return the
// current number of processes.
guint increment_process_count(void)
{
    // Attach to the process shm segment to increment the attach count.
    if (shmat(shmid, NULL, SHM_RDONLY) == MAP_FAILED) {
        g_critical("there was an error attaching to shmid %#x, %s.", shmid, g_strerror(errno));
        abort();
    }

    // Return to caller so that they can verify this is within bounds.
    return get_process_count();
}

// Get the current number of processes, but don't increment it.
guint get_process_count(void)
{
    struct shmid_ds shmds;

    // Stat the id to find the current count.
    if (shmctl(shmid, IPC_STAT, &shmds) == -1) {
        g_critical("there was an error stating the process counting shmid, %s", g_strerror(errno));
        abort();
    }

    // Return to caller so that they can verify this is within bounds.
    return shmds.shm_nattch;
}

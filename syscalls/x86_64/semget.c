#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Callback for typelib_add_resource().
static gboolean destroy_semaphore(guintptr semid)
{
    return semctl(semid, IPC_RMID, NULL) != -1;
}

// Get a semaphore set identifier.
// int shmget(key_t key, size_t size, int shmflg);
// XXX THIS DOESNT WORK, REWRITE
SYSFUZZ(semget, __NR_semget, SYS_DISABLED, CLONE_DEFAULT, 1000)
{
    glong  retcode;
    glong  semid = -1;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, &semid, __NR_semget,                                                                   // int
                                      typelib_get_integer_selection(2, IPC_PRIVATE, typelib_get_integer()),                  // key_t key
                                      typelib_get_integer(),                                                                 // size_t size
                                      typelib_get_integer_mask(IPC_CREAT | IPC_EXCL | SHM_HUGETLB | SHM_NORESERVE | 0777));  // int shmflg

    // Record the new shmid.
    if (retcode == ESUCCESS) {
        typelib_add_resource(this, semid, RES_SHMID, RF_NONE, destroy_semaphore);
    }

    return retcode;
}

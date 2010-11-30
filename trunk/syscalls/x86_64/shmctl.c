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

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Shared memory control.
// int shmctl(int shmid, int cmd, struct shmid_ds *buf);
SYSFUZZ(shmctl, __NR_shmctl, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gint     cmd;
    glong    retcode;
    gpointer buf;

    // Choose a command.
    cmd = typelib_get_integer_selection(8,
                                        IPC_INFO,
                                        IPC_SET,
                                        SHM_INFO,
                                        SHM_STAT,
                                        IPC_STAT,
                                        SHM_LOCK,
                                        SHM_UNLOCK,
                                        IPC_RMID);

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_shmctl,                                                // int
                                      typelib_get_resource(this, NULL, RES_SHMID, RF_NONE),             // int shmid
                                      cmd,                                                              // int cmd
                                      typelib_get_buffer(&buf, g_random_int_range(0, PAGE_SIZE)));      // struct shmid_ds *buf

    // Clean up.
    typelib_clear_buffer(buf);

    return retcode;
}

#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get process identification.
// pid_t getppid(void);
SYSFUZZ(getppid, SYS_getppid, SYS_SAFE | SYS_BORING, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_getppid);             // pid_t
}


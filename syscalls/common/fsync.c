#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Synchronize a file’s in-core state with storage device.
// int fsync(int fd);
// XXX: Slow.
SYSFUZZ(fsync, __NR_fsync, SYS_DISABLED, CLONE_DEFAULT, 0)
{
    return syscall_fast(__NR_fsync, typelib_get_resource(this, NULL, RES_FILE, RF_NONE));
}


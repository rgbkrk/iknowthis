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

// Commit buffer cache to disk.
// void sync(void);
SYSFUZZ(sync, __NR_sync, SYS_VOID | SYS_SAFE | SYS_DISABLED, CLONE_DEFAULT, 0)
{
	// Disabled as it's slow and trivial.
	return spawn_syscall_lwp(this, NULL, __NR_sync);                                                // void
}

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <linux/reboot.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Delete a loadable module entry.
SYSFUZZ(delete_module, __NR_delete_module, SYS_FAIL, CLONE_DEFAULT, 0)
{
	gpointer    name;
	gint        retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_delete_module,                             // caddr_t
	                            typelib_get_buffer(&name, g_random_int_range(0, 0x1000)));  // const char *name

    typelib_clear_buffer(name);

    return retcode;
}


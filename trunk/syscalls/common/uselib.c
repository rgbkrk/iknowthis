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

// Load shared library.
SYSFUZZ(uselib, __NR_uselib, SYS_NONE, CLONE_FORK, 1000)
{
	gchar   *library;
	gint     retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_uselib,                                    // int
	                            typelib_get_pathname(&library));                            // const char *library

    g_free(library);

    return retcode;
}


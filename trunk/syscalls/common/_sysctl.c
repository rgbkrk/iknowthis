#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <linux/sysctl.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Read/write system parameters.
// int _sysctl(struct __sysctl_args *args);
SYSFUZZ(_sysctl, __NR__sysctl, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong                   retcode;
    struct __sysctl_args    args = {
    	.oldval     = NULL,
    	.newval     = NULL,
    };

    // This system call is bizarre.
    typelib_get_buffer((gpointer) &args.name,      g_random_int_range(0, PAGE_SIZE));
    typelib_get_buffer((gpointer) &args.oldlenp,   g_random_int_range(0, PAGE_SIZE));

    if (g_random_boolean()) {
        typelib_get_buffer((gpointer) &args.oldval, g_random_int_range(0, PAGE_SIZE));
        args.nlen = typelib_get_integer();
    }

    if (g_random_boolean()) {
        typelib_get_buffer((gpointer) &args.newval, g_random_int_range(0, PAGE_SIZE));
        args.newlen = typelib_get_integer();
    }


    retcode = spawn_syscall_lwp(this, NULL, __NR__sysctl,   // int
                                &args);                     // struct __sysctl_args *args

    typelib_clear_buffer(args.name);
    typelib_clear_buffer(args.oldlenp);

    if (args.oldval) 
    	typelib_clear_buffer(args.oldval);

    if (args.newval) {
    	typelib_clear_buffer(args.newval);
    	
    	// I shouldn't be allowed to write a new value.
    	g_assert_cmpint(retcode, !=, ESUCCESS);
    }

    return retcode;
}


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
#include "resource.h"

// Open a performance event, associate it to a task/cpu.
// int perf_event_open(struct perf_event_attr *attr_uptr, pid_t puid, int cpu, int group_fd, unsigned long flags);
SYSFUZZ(perf_event_open, __NR_perf_event_open, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    attr_uptr;
    gint        retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_perf_event_open,                                 // int
                                typelib_get_buffer(&attr_uptr, g_random_int_range(0, PAGE_SIZE)), // struct perf_event_attr *attr_uptr
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),              // pid_t puid
                                typelib_get_integer(),                                            // int cpu
                                typelib_fd_get(this),                                             // int group_fd
                                typelib_get_integer_mask(3));                                     // unsigned long flags

    typelib_clear_buffer(attr_uptr);
    return retcode;
}


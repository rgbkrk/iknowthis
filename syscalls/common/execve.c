#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Execute program.
// int execve(const char *filename, char *const argv[], char *const envp[]);
SYSFUZZ(execve, __NR_execve, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    argv[2];
    gpointer    envp[2];
    gchar      *path    = g_strdup_printf("/proc/self/%d", (gint) typelib_get_resource(this, NULL, RES_FILE, RF_NONE));

    memset(argv, 0, sizeof(argv));
    memset(envp, 0, sizeof(envp));

    typelib_get_buffer(&argv[0], PAGE_SIZE);
    typelib_get_buffer(&envp[0], PAGE_SIZE);

    // Execute system call.
    retcode = spawn_syscall_lwp(this, NULL, __NR_execve, path, &argv, &envp);

    // Clean up
    g_free(path);
    typelib_clear_buffer(argv[0]);
    typelib_clear_buffer(envp[0]);

    return retcode;
}

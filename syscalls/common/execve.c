#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Execute program.
// int execve(const char *filename, char *const argv[], char *const envp[]);
SYSFUZZ(execve, __NR_execve, SYS_FAIL, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    guint       nargs;
    guint       nenv;
    gpointer   *argv;
    gpointer   *envp;
    gchar      *path;

    // Choose how many parameters to generate.
    nargs   = g_random_int_range(0, 128);
    nenv    = g_random_int_range(0, 128);

    // Allocate space for pointers.
    argv    = g_malloc0_n(nargs + 1, sizeof(gpointer));
    envp    = g_malloc0_n(nenv  + 1, sizeof(gpointer));

    // Allocate data.
    while (nenv)  typelib_get_buffer(&envp[--nenv], PAGE_SIZE);
    while (nargs) typelib_get_buffer(&argv[--nargs], PAGE_SIZE);

    // Execute system call.
    retcode = spawn_syscall_lwp(this, NULL, __NR_execve,                                      // int
                                typelib_get_pathname(&path),                                  // const char *filename
                                &argv,                                                        // char *const argv[]
                                &envp);                                                       // char *const envp[]

    // Clean up
    g_free(path);

    // Clear each arg.
    while (argv[nargs]) typelib_clear_buffer(argv[nargs++]);
    while (envp[nenv]) typelib_clear_buffer(envp[nenv++]);

    g_free(argv);
    g_free(envp);

    return retcode;
}

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
SYSFUZZ(execve, __NR_execve, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gint      retcode;
    gpointer  argv[] = { NULL, NULL };
    gpointer  envp[] = { NULL, NULL };
    gchar    *path;

    typelib_get_buffer(&argv[0], PAGE_SIZE);
    typelib_get_buffer(&envp[0], PAGE_SIZE);

    retcode = spawn_syscall_lwp(this, NULL, __NR_execve,                                      // int
                                typelib_get_pathname(&path),                                  // const char *filename
                                &argv,                                                        // char *const argv[]
                                &envp);                                                       // char *const envp[]

    g_free(path);
    typelib_clear_buffer(argv[0]);
    typelib_clear_buffer(envp[0]);

    return retcode;
}


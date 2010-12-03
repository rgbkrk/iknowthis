#ifndef __SYSFUZZ_H
#define __SYSFUZZ_H
#pragma once

#include <sys/mman.h>
#include <sched.h>

#ifndef PAGE_SIZE
# define PAGE_SIZE 0x1000
#endif

#ifndef CLONE_IO
# define CLONE_IO 0
#endif

// Custom errno values, must be <= 0. These are used to represent errors
// outside of errno, such as a process exited, or a timeout expiring.
enum {
    ESUCCESS        =  0,               // No error.
    ETIMEOUT        = -1,               // Timeout expired.
    EEXITED         = -2,               // Fuzzer exited.
    EKILLED         = -3,               // Fuzzer was killed.
};

// Flags that modify the behaviour of a fuzzer.
// If you modify this list, remember to update any pretty printers that dump
// these flags, like list_fuzzer_names().
enum {
    SYS_NONE        = 0,
    SYS_DISABLED    = 1 << 0,           // Fuzzer is disabled.
    SYS_FAIL        = 1 << 1,           // Failure is expected, warn on success.
    SYS_TIMEOUT     = 1 << 2,           // Timeout is expected.
    SYS_VOID        = 1 << 3,           // Fuzzer does not return a useful value. (e.g. exit).
    SYS_BORING      = 1 << 4,           // Fuzzer expected to always return the same value.
    SYS_SAFE        = 1 << 5,           // Fuzzer is safe to run without separation.
};

// Some convenience clone combinations.
enum {
    CLONE_FORK      = 0,
    CLONE_DEFAULT   = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_SYSVSEM | CLONE_IO,
    CLONE_SAFER     = CLONE_FS | CLONE_FILES | CLONE_IO,
};

// No way any syscall can return more than this number of errors.
#define MAX_ERROR_CODES 128

typedef struct {
    gulong      error;                              // Errno value
    gulong      count;                              // Number of times seen.
} error_record_t;

typedef struct {
    glong          (*callback)(gpointer);           // Fuzzer subroutine.
    gchar           *name;                          // System call or fuzzer name
    guint           flags;                          // Fuzzer flags.
    guint           total;                          // Total number of executions.
    guint           failures;                       // Total number of failures.
    guint           shared;                         // Flags for clone(2) describing what it's safe share.
    guint           number;                         // Syscall number, used for debugging.
    guint           timeout;                        // Microseconds allowed to execute for.
    gdouble         average;                        // Average time fuzzer takes to execute.
    gsize           numerrors;                      // Unique error codes recorded.
    error_record_t  errors[MAX_ERROR_CODES];        // error statistics.
} syscall_fuzzer_t;

// Wrapper function around syscall() to return errno.
#define syscall_fast(_number...)                                            \
(                                                                           \
    errno = 0,                                      /* Reset error code */  \
    syscall(_number),                               /* Execute syscall */   \
    errno                                           /* Return error code */ \
)

// The same, but if we want the return value as well.
#define syscall_fast_ret(_dest, _number...)                                 \
(                                                                           \
    errno = 0,                                      /* Reset errno */       \
    *((glong *)(_dest)) = syscall(_number),         /* Execute syscall */   \
    errno                                           /* Return error code */ \
)

// Record the highest syscall number for this architecture.
#if defined(__i386__)
# define MAX_SYSCALL_NUM 338
#elif defined(__x86_64__)
# define MAX_SYSCALL_NUM 300
#else
# warning please define a real MAX_SYSCALL_NUMBER for this architecure
# define MAX_SYSCALL_NUM 300
#endif

#define MAX_PROCESS_NUM 32

extern syscall_fuzzer_t *system_call_fuzzers;
extern gint              semid;                 // Semaphore set for syscall fuzzers.

// Alocate space for the system_call_fuzzer table in shared memory.
static inline void allocate_sycall_fuzzer_table(void)
{
    g_assert(system_call_fuzzers == NULL);

    system_call_fuzzers = mmap(NULL, sizeof(syscall_fuzzer_t) * MAX_SYSCALL_NUM,
                                     PROT_READ | PROT_WRITE,
                                     MAP_SHARED | MAP_ANONYMOUS,
                                     -1,
                                     0);
}

#define SYSFUZZ(_name, _syscall, _flags, _cloneflags, _timeout)             \
    static glong __fuzz__ ## _name (gpointer ignored);                      \
    static void __constructor __const__ ## _name (void)                     \
    {                                                                       \
        /* Verify the system call table is ready */                         \
        if (system_call_fuzzers == NULL)                                    \
            allocate_sycall_fuzzer_table();                                 \
                                                                            \
        /* Verify this slot is empty */                                     \
        g_assert_cmpstr(system_call_fuzzers[_syscall].name, ==, NULL);      \
                                                                            \
        system_call_fuzzers[_syscall].callback = __fuzz__ ## _name;         \
        system_call_fuzzers[_syscall].name     = # _name;                   \
        system_call_fuzzers[_syscall].flags    = _flags;                    \
        system_call_fuzzers[_syscall].shared   = _cloneflags;               \
        system_call_fuzzers[_syscall].timeout  = _timeout;                  \
        system_call_fuzzers[_syscall].number   = _syscall;                  \
        return;                                                             \
    }                                                                       \
    static glong __fuzz__ ## _name (gpointer this)

#else
# warning sysfuzz.h included twice
#endif

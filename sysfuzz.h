#ifndef __SYSFUZZ_H
#define __SYSFUZZ_H

#include <sched.h>

#ifndef PAGE_SIZE
# define PAGE_SIZE 0x1000
#endif

#ifndef CLONE_IO
# define CLONE_IO 0
#endif

// Customer errno values, must be <= 0. These are used to represent errors
// outside of errno, such as a process exited, or a timeout expiring.
enum {
    ESUCCESS        =  0,               // No error.
    ETIMEOUT        = -1,               // Timeout expired.
    EEXITED         = -2,               // Fuzzer exited.
    EKILLED         = -3,               // Fuzzer was killed.
};

// Flags that modify the behaviour of a fuzzer.
enum {
    SYS_NONE        = 0,
    SYS_DISABLED    = 1 << 0,           // Fuzzer is disabled.
    SYS_FAIL        = 1 << 1,           // Failure is expected, warn on success.
    SYS_TIMEOUT     = 1 << 2,           // Timeout is expected.
    SYS_VOID        = 1 << 3,           // Fuzzer does not return a useful value.
    SYS_BORING      = 1 << 4,           // Fuzzer will always return the same value.
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
    guint       error;                              // Errno value
    guint       count;                              // Number of times seen.
} error_record_t;

typedef struct {
    gint           (*callback)(gpointer);           // Fuzzer subroutine.
    gchar           *name;                          // System call or fuzzer name
    guint           flags;                          // Fuzzer flags.
    guint           total;                          // Total number of executions.
    guint           failures;                       // Total number of failures.
    guint           shared;                         // Flags for clone(2) describing what it's safe share.
    guint           number;                         // Syscall number, used for debugging.
    guint           timeout;                        // Microseconds allowed to execute for.
    gdouble         average;                        // Average time fuzzer takes to execute.
    gsize           numerrors;                      // Unique error codes recorded.
    pid_t           pid;                            // Process Id of last fuzzer.
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
    *((int *)(_dest)) = syscall(_number),           /* Execute syscall */   \
    errno                                           /* Return error code */ \
)

#define MAX_SYSCALL_NUM 338
#define MAX_PROCESS_NUM 32

extern syscall_fuzzer_t system_call_fuzzers[MAX_SYSCALL_NUM];
extern guint            total_registered_fuzzers;
extern guint            total_disabled_fuzzers;
extern guint            process_nesting_depth;

#define SYSFUZZ(_name, _syscall, _flags, _cloneflags, _timeout)             \
    static gint __fuzz__ ## _name (gpointer ignored);                       \
    static void __constructor __const__ ## _name (void)                     \
    {                                                                       \
        /* Verify this slot is empty */                                     \
        g_assert_cmpstr(system_call_fuzzers[_syscall].name, ==, NULL);      \
        if ((_flags) & SYS_DISABLED) {                                      \
            total_disabled_fuzzers++;                                       \
        } else {                                                            \
            total_registered_fuzzers++;                                     \
        }                                                                   \
        system_call_fuzzers[_syscall].callback = __fuzz__ ## _name;         \
        system_call_fuzzers[_syscall].name     = # _name;                   \
        system_call_fuzzers[_syscall].flags    = _flags;                    \
        system_call_fuzzers[_syscall].shared   = _cloneflags;               \
        system_call_fuzzers[_syscall].timeout  = _timeout;                  \
        system_call_fuzzers[_syscall].number   = _syscall;                  \
        return;                                                             \
    }                                                                       \
    static gint __fuzz__ ## _name (gpointer this)

#else
# warning sysfuzz.h included twice
#endif

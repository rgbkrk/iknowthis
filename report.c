#include <stdbool.h>
#include <search.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <sched.h>
#include <stdio.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

syscall_fuzzer_t   system_call_fuzzers[MAX_SYSCALL_NUM]; // Fuzzer definitions for each system call.
guint              total_registered_fuzzers;             // Total number of registered fuzzers.
guint              total_disabled_fuzzers;               // Number of fuzzers that have been disabled.

void prettyprint_fuzzer(FILE *output, syscall_fuzzer_t *fuzzer)
{
	guint i;

    fprintf(output, "Statistics for %s follow\n", fuzzer->name);
    fprintf(output, "\tTotal:       %u\n", fuzzer->total);
    fprintf(output, "\tFailure:     %u\n", fuzzer->failures);
    fprintf(output, "\tSuccess:     %u\n", fuzzer->total - fuzzer->failures);
    fprintf(output, "\tSpeed:       %f\n", fuzzer->average);

    fprintf(output, "\tError Code Distribution:\n");

    // Dump all the known errors for this fuzzer.
    for (i = 0; i < fuzzer->numerrors; i++) {
    	fprintf(output,"\t\t%10u\t%10d\t%s\n",
    	        fuzzer->errors[i].count,
    	        fuzzer->errors[i].error,
    	        g_strerror(fuzzer->errors[i].error));
    }

    fprintf(output, "\n");
    return;
}

void create_fuzzer_report(void)
{
    FILE    *report;
    time_t   timestamp = time(0);
    guint    count;
    guint    i;
    
    g_message("generating progress report");

    if ((report = fopen("/tmp/iknowthis.txt", "w+")) == NULL) {
    	fprintf(stderr, "unable to open report file, %m\n");
    	return;
    }
    
    g_assert(report);

    fprintf(report, "iknowthis report generated on by process %u.\n\nDate: %s\n",
                    getpid(),
                    ctime(&timestamp));
                    

    fprintf(report, "The following system call numbers do not have fuzzers\n"
                    "associated with them.\n\n");

    for (count = 0, i = 0; i < MAX_SYSCALL_NUM; i++) {
        if (system_call_fuzzers[i].callback == NULL) {
            fprintf(report, "%s%u%s", count % 8 == 0 ? "\t" : " ",
                                      i,
                                      count % 8 == 7 ? "\n" : ",");
            count++;
        }
    }

    fprintf(report, "\n\n");
    fprintf(report, "The following fuzzers have been disabled are not being\n"
                    "tested.\n\n");

    for (count = 0, i = 0; i < MAX_SYSCALL_NUM; i++) {
        if (system_call_fuzzers[i].flags & SYS_DISABLED) {
            fprintf(report, "%s%s%s", count % 8 == 0 ? "\t" : " ",
                                      system_call_fuzzers[i].name,
                                      count % 8 == 7 ? "\n" : ",");
            count++;
        }
    }

    fprintf(report, "\n\n");
    fprintf(report, "The following fuzzers have never succeeded, but are not\n"
                    "marked SYS_FAIL.\n\n"
                    "If you do not expect these fuzzers to succeed (for example,\n"
                    "they require privileges), please annotate them accordingly.\n\n");

    for (count = 0, i = 0; i < MAX_SYSCALL_NUM; i++) {
        if (system_call_fuzzers[i].callback == NULL)
            continue;
        if (system_call_fuzzers[i].flags & SYS_DISABLED)
            continue;
        if (system_call_fuzzers[i].flags & SYS_FAIL)
            continue;

        if (system_call_fuzzers[i].total == system_call_fuzzers[i].failures) {
            fprintf(report, "%s%s%s", count % 8 == 0 ? "\t" : " ",
                                      system_call_fuzzers[i].name,
                                      count % 8 == 7 ? "\n" : ",");
            count++;
        }
    }

    fprintf(report, "\n\n");
    fprintf(report, "The following fuzzers always return the same value, and may not be\n"
                    "achieving the desired level of coverage.\n\n");

    for (count = 0, i = 0; i < MAX_SYSCALL_NUM; i++) {
        if (system_call_fuzzers[i].callback == NULL)
            continue;
        if (system_call_fuzzers[i].flags & SYS_DISABLED)
            continue;
        if (system_call_fuzzers[i].flags & SYS_BORING)
        	continue;
        if (system_call_fuzzers[i].flags & SYS_VOID)
        	continue;

        if (system_call_fuzzers[i].failures == 0 
                || (system_call_fuzzers[i].failures == system_call_fuzzers[i].total 
                        && system_call_fuzzers[i].numerrors == 1)) {
            fprintf(report, "%s%s%s", count % 8 == 0 ? "\t" : " ",
                                      system_call_fuzzers[i].name,
                                      count % 8 == 7 ? "\n" : ",");
            count++;
        }
    }

    fprintf(report, "\n\n");
    fprintf(report, "The following fuzzers are marked boring, but have returned multiple values\n\n");

    for (count = 0, i = 0; i < MAX_SYSCALL_NUM; i++) {
        if (system_call_fuzzers[i].callback == NULL)
            continue;
        if (system_call_fuzzers[i].flags & SYS_DISABLED)
            continue;
        if (!(system_call_fuzzers[i].flags & SYS_BORING))
            continue;
        if (system_call_fuzzers[i].numerrors > 1 || (system_call_fuzzers[i].numerrors == 1 && system_call_fuzzers[i].failures < system_call_fuzzers[i].total)) {
            fprintf(report, "%s%s%s", count % 8 == 0 ? "\t" : " ",
                                      system_call_fuzzers[i].name,
                                      count % 8 == 7 ? "\n" : ",");
            count++;
        }
    }

    fprintf(report, "\n\n");
    fprintf(report, "Detailed statistics for all fuzzers follows.\n\n\n");

    for (i = 0; i < MAX_SYSCALL_NUM; i++) {
        if (system_call_fuzzers[i].callback == NULL)
            continue;
        if (system_call_fuzzers[i].flags & SYS_DISABLED)
            continue;
        prettyprint_fuzzer(report, &system_call_fuzzers[i]);
    }

    fclose(report);

    return;
}

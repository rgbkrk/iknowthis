#include <stdbool.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <glib.h>

#include "sysfuzz.h"
#include "iknowthis.h"

void create_dirty_pages(void)
{
	guint i;

    if (fork() != 0) {
        return;
    }

    // Start allocating pages, storing them in an slist.
    while (true) {
    	guint64 *newpage = mmap(GUINT_TO_POINTER(g_random_int()),
    	                        PAGE_SIZE,
    	                        PROT_READ | PROT_WRITE,
    	                        MAP_ANONYMOUS | MAP_PRIVATE,
    	                        -1,
    	                        0);

    	// Write secret to it.
    	for (i = 0; i < (PAGE_SIZE / sizeof(guint64)); i++) {
    		newpage[i] = SECRET;
        }

        usleep(1000);
    }

    g_assert_not_reached();
}


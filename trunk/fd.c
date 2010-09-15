#include <glib.h>
#include <glib/gprintf.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>

#include "sysfuzz.h"
#include "typelib.h"

// All file descriptors created by fuzzers are stored in a linked list.
//
// Each new file descriptor is associated with a linked list of actions that
// have occurred on that file descriptor, along with a snapshot of how it
// looked at that time.
//
// This should allow us to recreate the life of a file descriptor.

struct descriptor {
	gint     fd;                            // File Descriptor.
	gint     flags;                         // Any flags to modify typelib behaviour.
	GSList  *trace;                         // List of actions.
};

struct trace {
	syscall_fuzzer_t    *caller;            // Caller.
	time_t               timestamp;         // Timestamp when this action occurred.
	gint                 flags;             // F_GETFL at time of call.
	guint                offset;            // Read/Write offset at time of call.
	struct stat          stat;              // Stat buffer at time of call.
	gchar               *description;       // Readlink of /proc/self/fd/%d at time of call.
	// XXX: socket options.
};

static GSList *file_descriptor_list;    // A record of open file descriptors.

// How many file descriptors should i remember?
#define MAX_FILE_DESCRIPTORS 128

static struct trace *typelib_fd_trace(syscall_fuzzer_t *this, gint fd);
static gint          typelib_fd_compare_descriptor(gconstpointer a, gconstpointer b);
static void          typelib_fd_destroy_descriptor(struct descriptor *file, gboolean closefd);
static void          typelib_fd_pretty_print(struct descriptor *file);


// Learn about a new file descriptor, saving into a linked list.
void typelib_fd_new(syscall_fuzzer_t *this, gint fd, gint flags)
{
    struct descriptor *file = g_malloc(sizeof *file);
    GSList            *node = NULL;

    if (fd < 0) {
    	g_debug("fuzzer %s registered illegal file descriptor", this->name);
    }

    g_assert_cmpint(fd, >=, 0);

    g_assert(this);

    // Create a record of the new file descriptor.
    file->fd            = fd;
    file->flags         = flags;
    file->trace         = g_slist_append(NULL, typelib_fd_trace(this, fd));
    node                = g_slist_find_custom(file_descriptor_list,
                                              file,
                                              typelib_fd_compare_descriptor);

    // Verify this descriptor doesn't already appear in the list.
    if (node != NULL) {
    	// This shouldn't happen, another fuzzer closed an fd without reporting it.
    	g_warning("fuzzer %s attempted to add already known fd %d to global list",
    	          this->name,
    	          fd);

        // Show a debugging trace.
        typelib_fd_pretty_print(node->data);

        // Don't continue, list may be in inconsistent state.
        abort();
    }

    // Check if we should perform additional sanity checks.
    if (file->flags & FD_DEBUG) {
    	// XXX: Check if the trace object looks sane.
    	g_debug("fuzzer %s created new debug file descriptor %d", this->name, fd);
        
        // Dump the new object.
    	typelib_fd_pretty_print(file);
    }

    // Record this new file descriptor.
    file_descriptor_list = g_slist_append(file_descriptor_list, file);

    // Check if I need to close one.
    if (g_slist_length(file_descriptor_list) > MAX_FILE_DESCRIPTORS) {
        // I do, choose a random node to delete.
        // XXX: Note that this may select the file I just added, so the pointer
        //      may not be valid after this.
        GSList *node = g_slist_nth(file_descriptor_list, 
                                   g_random_int_range(0,
                                   g_slist_length(file_descriptor_list)));

        // Close fd and destroy record.
        typelib_fd_destroy_descriptor(node->data, true);

        // Delete from list.
        file_descriptor_list = g_slist_delete_link(file_descriptor_list, node);
    }

    g_assert_cmpint(g_slist_length(file_descriptor_list), <=, MAX_FILE_DESCRIPTORS);
    g_assert_cmpint(g_slist_length(file_descriptor_list), >=, 1);

    return;
}

// Report that an fd has been closed and should be removed from the list.
void typelib_fd_stale(syscall_fuzzer_t *this, gint fd, gint flags)
{
	struct descriptor *file;
	GSList            *node;
	
    g_assert(this);

	// Find this descriptor in the list.
	node  = g_slist_find_custom(file_descriptor_list,
	                            &fd,
	                            typelib_fd_compare_descriptor);
    
    // Sanity checks.
    g_assert(node);
    g_assert(node->data);

    // Get the descriptor struct out of list node.
	file = node->data;

    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(file->fd, ==, fd);

    // Check if debugging requested.
    if (file->flags & FD_DEBUG) {
        g_debug("fuzzer %s reports descriptor %d is stale.", this->name, fd);

        // Show a trace.
        typelib_fd_pretty_print(file);
    }

    // Remove from the list.
    file_descriptor_list = g_slist_delete_link(file_descriptor_list, node);
    
    // Verify it only appeared in the list once.
    g_assert(!g_slist_find_custom(file_descriptor_list,
                                  file,
                                  typelib_fd_compare_descriptor));
    
    // Destroy the record for this file.
    typelib_fd_destroy_descriptor(file, false);

    return;
}

// Return a random fd from the list.
gint typelib_fd_get(syscall_fuzzer_t *this)
{
	struct descriptor *file;
	guint              len;

    // Sanity checks.
    g_assert(this);

    // Check I have some file descriptors available.
    if ((len = g_slist_length(file_descriptor_list))) {

    	// I do, Choose a random list element.
	    GSList *node = g_slist_nth(file_descriptor_list,
	                               g_random_int_range(0,
	                               len));
        
        // Check it looks sane.
        g_assert(node);
        g_assert(node->data);

	    // Grab the descriptor struct from list node.
	    file = node->data;
    } else {
        // I don't know how else this can fail.
    	g_assert_cmpint(len, ==, 0);
        
        // Okay, use an invalid number.
        return -1;
    }

    // Must be at least one trace.
    g_assert(file->trace);

    // Must look valid.
    g_assert_cmpint(file->fd, >=, 0);

    // Record trace for debugging.
    file->trace = g_slist_append(file->trace,
                                 typelib_fd_trace(this, file->fd));

    // Finished.
    return file->fd;
}

// Return a pointer to a trace structure for this fd.
static struct trace *typelib_fd_trace(syscall_fuzzer_t *this, gint fd)
{
	struct trace *trace     = g_malloc0(sizeof *trace);
	gchar        *procpath  = g_alloca(32);
	GError       *error     = NULL;
    
    g_assert(this);
    g_assert_cmpint(fd, >=, 0);

    g_sprintf(procpath, "/proc/self/fd/%d", fd);

    // Take a snapshot of the state of this fd.
    fstat(fd, &trace->stat);

    trace->caller       = this;
    trace->timestamp    = time(0);
    trace->flags        = fcntl(fd, F_GETFL);
    trace->offset       = lseek(fd, 0, SEEK_CUR);
    trace->description  = g_file_read_link(procpath, &error);

    // FIXME: Change this so i get a copy of file so i can pretty print the trace.
    if (error) {
    	g_critical("fuzzer %s attempted to add trace for fd %u, but it didn't exist",
    	           this->name,
    	           fd);
    }

    return trace;
}

// Clean up a released descriptor.
static void typelib_fd_destroy_descriptor(struct descriptor *file, gboolean closefd)
{
    // GFunc used to destroy trace list.
    void typelib_fd_destroy_trace(gpointer data, gpointer user)
    {
        struct trace *trace = data;
        g_free(trace->description);
        g_free(trace);
    }

    // Close the file descriptor if requested.
    if (closefd && close(file->fd) != 0) {
    	// Dump some debugging information.
        g_warning("failed to close file descriptor %d, %s", file->fd, g_strerror(errno));
        typelib_fd_pretty_print(file);
        abort();
    }

    // Clean up the element, start with the trace list elements.
    g_slist_foreach(file->trace, typelib_fd_destroy_trace, NULL);

    // Clean up the list itself.
    g_slist_free(file->trace);

    // And finally release the descriptor.
    g_free(file);

    return;
}

// Dump the contents of a descriptor for debugging.
static void typelib_fd_pretty_print(struct descriptor *file)
{
    GSList *node = file->trace;
    gchar  *date = g_alloca(26);
    guint   i    = 0;

    g_debug("Dump of file descriptor %d follows.", file->fd);
    g_debug("\tTrace Length:         %u", g_slist_length(node));
    g_debug("\tFlags Set:            %u", file->flags);
    g_debug("\tFile Object:          %p", file);
    g_debug("\tTrace List Head:      %p", node);

    // Dump the trace list for this fd.
    while (node) {
    	struct trace *trace;
    	
    	trace = node->data;
    	node  = node->next;

        // Read the timestamp.
        ctime_r(&trace->timestamp, date);

    	g_debug("%3u. %s %s %s",
    	    i++,
    	    trace->caller->name,
    	    trace->description,
    	    g_strchomp(date));
    }
}

// GCompareFunc for file descriptors.
static gint typelib_fd_compare_descriptor(gconstpointer a, gconstpointer b)
{
    return ((const struct descriptor *)(a))->fd
        - ((const struct descriptor *)(b))->fd;
}

// Count how many file descriptors this process has open that are not in my
// list. This number should remain fairly static, and so can be used for
// tracking down leaks.
guint typelib_fd_count_unmanaged(void)
{
    GDir *dir = g_dir_open("/proc/self/fd", 0, NULL);
    guint  i  = 0;

    while (g_dir_read_name(dir))
    	i++;

    g_assert_cmpint(i, >=, g_slist_length(file_descriptor_list));

    g_dir_close(dir);

    return i - g_slist_length(file_descriptor_list);
}

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#ifndef _XOPEN_SOURCE
# define _XOPEN_SOURCE 500
#endif

#include <stdbool.h>
#include <stdio.h>
#include <glib.h>
#include <string.h>
#include <ftw.h>

#include "sysfuzz.h"
#include "typelib.h"

//
// Routines for choosing interesting paths.
//

static GPtrArray * fs_mount_points;

static void __constructor typelib_find_mount_points(void)
{
	gchar *mounts;
	gchar *position;
	gchar *mountpoint;
	gchar *filesystem;
	gsize  length;

    // Create a cleanup routine.
    void __destructor fini(void)
    {
    	g_ptr_array_free(fs_mount_points, true);
    }

    // Read the mounted filesystems.
	if (g_file_get_contents("/proc/mounts", &mounts, &length, NULL) == false) {
		g_error("unable to read mounted filesystems");
    }

    fs_mount_points = g_ptr_array_new();
    position        = mounts;
    mountpoint      = g_malloc(length);
    filesystem      = g_malloc(length);

    // Parse out mountpoints.
    while (sscanf(position, "%*s %s %s %*s %*u %*u", mountpoint, filesystem) >= 1) {
    	// Check if I should blacklist this filesystem
        if (g_strcmp0(filesystem, "vmhgfs") != 0 && g_strcmp0(filesystem, "nfs") != 0) {
            // Duplicate this string and add to array.
            g_ptr_array_add(fs_mount_points, g_strdup(mountpoint));
        }

        // Advance past next newline, unless it's found the terminating nul.
        if (*(position = strchrnul(position, '\n'))) {
        	position++;
        }
    }

    // Finished.
    g_free(mounts);
    g_free(mountpoint);
    g_free(filesystem);

    g_debug("discovered %u mountpoints from /proc/mounts", fs_mount_points->len);

    // There should always be at least one filesystem.
    g_assert_cmpuint(fs_mount_points->len, >, 0);
        
    return;
}

gchar * typelib_get_pathname(gchar **pathname)
{
    const gchar *root;

    // Callback for nftw.
    int file_tree_callback(const char *fpath,
                           const struct stat *sb,
                           int typeflag,
                           struct FTW *ftwbuf)
    {
    	// If we're at a reasonable depth, it's okay to break out
    	// of directories.
    	if (ftwbuf->level > 2) {
    		switch (g_random_int_range(0, 512)) {
    			case   0 ... 31: return FTW_SKIP_SUBTREE;
    			case  32 ... 64: return FTW_SKIP_SIBLINGS;
            }
        }

        // Otherwise, continue most of the time.
        if (g_random_int_range(0, 16))
        	return FTW_CONTINUE;

        // Okay, this will do.

        // Older versions of nftw set fpath differently, differentiate by
        // checking for absolute vs relative pathname.
        if (g_str_has_prefix(fpath, G_DIR_SEPARATOR_S)) {
            *pathname = g_strdup(fpath);
        } else {
            *pathname = g_strjoin(NULL, root, G_DIR_SEPARATOR_S, fpath, NULL);
        }
        
        // g_debug("selected %s as random filesystem entry, requesting FTW_STOP", *pathname);

        // Signal end.
        return FTW_STOP;
    }

    // Choose a random mountpoint.
    root = g_ptr_array_index(fs_mount_points, g_random_int_range(0, fs_mount_points->len));

    // g_debug("selected mountpoint %s for random pathname", root);

    // Begin Filesystem Walk.
    if (nftw(root, file_tree_callback, 32, FTW_DEPTH | FTW_ACTIONRETVAL | FTW_MOUNT | FTW_PHYS) != FTW_STOP) {
        gchar junk[PATH_MAX * 2] = {0};

    	// Reached the end of the tree. Okay, make something up.
        *pathname = g_strdup_printf("%s%s%s", root,
                                              G_DIR_SEPARATOR_S,
                                              typelib_random_buffer(junk, sizeof junk - 1));
        // g_debug("selected %s as random filesystem entry due to nftw completion", *pathname);
    }

    // Complete.
    return *pathname;
}

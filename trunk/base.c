#include <sys/uio.h>
#include <glib.h>

#include "sysfuzz.h"
#include "typelib.h"


// 
// typelib routines for primitive types.
//

guint typelib_get_integer(void)
{
	switch (g_random_int_range(0, 3)) {
		case 0: return g_random_int() & g_random_int();
		case 1: return g_random_int() | g_random_int();
		case 2: return g_random_int();
    }

    g_assert_not_reached();
}
 
// Note that it might return out of range occasionally.
guint typelib_get_integer_range(guint start, guint end)
{
	g_assert_cmpuint(start, <, end);
	
	if (g_random_int_range(0, 1024)) {
		return g_random_int_range(start, end + 1);
    }

    return typelib_get_integer();
}

guint typelib_get_integer_selection(guint count, ...)
{
    va_list     ap;
    guint       i;
    guint       current;
    guint       selected;

    // Possibly break the rules.
    if (g_random_int_range(0, 1024) == 0) {
        return typelib_get_integer();
    }

    // Choose a random argument.
    selected = g_random_int_range(0, count);
    i        = 0;

    va_start(ap, count); {
        do {
           current = va_arg(ap, guint);
        } while (++i < selected);
    } va_end(ap);

    return current;
}

guint typelib_get_integer_mask(guint mask)
{
    return typelib_get_integer() & mask;
}

gpointer typelib_get_iovec(gpointer *iov, gint *count, guint flags)
{
    guint         i;
    struct iovec *vec;

    *count  = g_random_int_range(0, 8);
    vec     = typelib_get_buffer(iov, *count * sizeof(struct iovec));

    for (i = 0; i < *count; i++) {
        vec[i].iov_len    = g_random_int_range(0, PAGE_SIZE);
        vec[i].iov_base   = typelib_get_buffer(NULL, vec[i].iov_len);
    }

    return vec;
}

void typelib_clear_iovec(gpointer iovec, gint count, guint flags)
{
    guint         i;
    struct iovec *p = iovec;

    for (i = 0; i < count; i++) {
        typelib_clear_buffer(p[i].iov_base);
    }

    typelib_clear_buffer(p);

    return;
}

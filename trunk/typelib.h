#ifndef __TYPELIB_H
#define __TYPELIB_H

#ifndef __constructor
# define __constructor __attribute__((constructor))
#endif
#ifndef __destructor
# define __destructor __attribute__((destructor))
#endif

#ifndef g_assert_cmpstr
# define g_assert_cmpstr(x, y, z) 
# define g_assert_cmpuint(x, y, z) 
# define g_assert_cmpint(x, y, z) 
# define guintptr unsigned
# define gintptr signed
# define g_strcmp0 strcmp
# define O_CLOEXEC 04
#endif

gpointer        typelib_random_buffer(gpointer buffer, gsize size);
gpointer        typelib_get_buffer(gpointer *buffer, gsize size);
gchar *         typelib_get_pathname(gchar **pathname);
guint           typelib_get_integer(void);
guint           typelib_get_integer_range(guint start, guint end);
void            typelib_clear_buffer(gpointer buffer);
guint           typelib_get_integer_selection(guint count, ...);
guint           typelib_get_integer_mask(guint mask);

enum {
    IOV_NONE           = 0,
};

gpointer        typelib_get_iovec(gpointer *iov, gint *count, guint flags);
void            typelib_clear_iovec(gpointer iovec, gint count, guint flags);

// File descriptors.
enum {
	FD_NONE             = 0,
	FD_DEBUG            = 1 << 0,
};

    // Main.
    void            typelib_fd_new(syscall_fuzzer_t *this, gint fd, gint flags);
    void            typelib_fd_stale(syscall_fuzzer_t *this, gint fd, gint flags);
    gint            typelib_fd_get(syscall_fuzzer_t *this);
    
    // Debugging.
    guint           typelib_fd_count_unmanaged(void);

// Vmas.
enum {
	VMA_NONE            = 0,
	VMA_DEBUG           = 1 << 0,
	VMA_HUGE            = 1 << 1,
};

    // Main.
    void            typelib_vma_new(syscall_fuzzer_t *this, guintptr address, gsize size, gint flags);
    void            typelib_vma_stale(syscall_fuzzer_t *this, guintptr address);
    guintptr        typelib_get_vma(syscall_fuzzer_t *this, guintptr *address, gsize *size);

#else
# warning typelib.h included twice
#endif


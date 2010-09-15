CFLAGS	    =-m32 -Wall -pipe -O2 `pkg-config --cflags glib-2.0`
LDFLAGS	    =-m32 -Wall -pipe -O2 `pkg-config --libs glib-2.0` 
CPPFLAGS    =-I. -Itypelib

# This glob matches all source files in the syscalls subdirectory.
SYSCALLS    = $(patsubst %.c,%.o,$(wildcard syscalls/*.c))

# Default rule.
all:        iknowthis

iknowthis:  $(SYSCALLS) iknowthis.o base.o buffer.o typelib/pathname.o \
            typelib/resource.o lwp.o vma.o maps.o proc.o
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f *.o $(SYSCALLS) iknowthis core.* core typelib/*.o

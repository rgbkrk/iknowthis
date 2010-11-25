CFLAGS	    =-Wall -pipe -O0 -ggdb3 -fno-strict-aliasing `pkg-config --cflags glib-2.0` -std=gnu99
LDFLAGS	    =-Wall -pipe -O0 -ggdb3 -fno-strict-aliasing `pkg-config --libs glib-2.0` -std=gnu99
CPPFLAGS    =-I. -Itypelib

# This glob matches all source files in the syscalls subdirectory.
SYSCALLS    = $(patsubst %.c,%.o,$(wildcard syscalls/$(shell uname -m)/*.c))

# Default rule.
all:        iknowthis

iknowthis:  $(SYSCALLS) iknowthis.o base.o buffer.o typelib/pathname.o \
            typelib/resource.o lwp.o vma.o maps.o proc.o
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f *.o syscalls/*/*.o iknowthis core.* core typelib/*.o

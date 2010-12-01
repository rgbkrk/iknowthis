# iknowthis requires the glib2, and clearsilver packages.
#
#    Fedora:    yum install clearsilver-devel glib2-devel zlib-devel libmicrohttpd-devel
#    Debian:    apt-get install clearsilver-dev libglib2.0-dev libmicrohttpd-dev
##

CFLAGS      =-Wall -pipe -O0 -ggdb3 -fno-strict-aliasing `pkg-config --cflags libmicrohttpd,glib-2.0` -std=gnu99
LDFLAGS     =-Wall -pipe -O0 -ggdb3 -fno-strict-aliasing `pkg-config --libs libmicrohttpd,glib-2.0` -std=gnu99 -lneo_cs -lneo_cgi -lneo_utl -lz
CPPFLAGS    =-I. -Itypelib -I/usr/include/ClearSilver
ARCH       ?=$(shell uname -m)

# This glob matches all source files in the syscalls subdirectory.
SYSCALLS    = $(patsubst %.c,%.o,$(wildcard syscalls/$(ARCH)/*.c))

# Default rule.
all:        iknowthis

iknowthis:  $(SYSCALLS) iknowthis.o base.o buffer.o typelib/pathname.o \
            typelib/resource.o lwp.o vma.o maps.o proc.o report.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o syscalls/*/*.o iknowthis core.* core typelib/*.o

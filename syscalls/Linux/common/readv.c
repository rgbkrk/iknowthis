#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Read or write data into multiple buffers.
// ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
// XXX FIXME
SYSFUZZ(readv, __NR_readv, SYS_DISABLED, CLONE_DEFAULT, 0)
{
	return 0;
}


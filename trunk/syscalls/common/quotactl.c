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

// Manipulate file quotas.
// long quotactl(int cmd, char *special, qid_t id, caddr_t addr);
// XXX FIXME
SYSFUZZ(quotactl, __NR_quotactl, SYS_NONE, CLONE_DEFAULT, 0)
{
	return 0;
}


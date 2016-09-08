#ifndef __SHIMS__
#define __SHIMS__

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define OPLIST                                                                 \
	X(read)                                                                    \
	X(write)

typedef ssize_t (*type_read)(int fildes, void *buf, size_t nbyte);
typedef ssize_t (*type_write)(int fildes, const void *buf, size_t nbyte);
// declare libc functions
#define X(n) type_##n libc_##n;
OPLIST
#undef X

#endif

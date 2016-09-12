#include "shims.h"
#include <string.h>
#include <unistd.h>

static inline void safe_print(const char *message) {
	write(1, message, strlen(message));
}

ssize_t read(int fd, void *buf, size_t count) {
	// safe_print("shim called\n");
	return libc_read(fd, buf, count);
}

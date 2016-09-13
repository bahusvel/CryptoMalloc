#include "camalloc.h"
#include "shims.h"
#include <string.h>
#include <unistd.h>

ssize_t read(int fd, void *buf, size_t count) {
	ca_nocipher(buf);
	ssize_t result = libc_read(fd, buf, count);
	/*
	if (fd == 0) {
		safe_print("Intercepted:");
		write(1, buf, count);
		write(1, "\n", 1);
	}
	*/
	ca_recipher(buf);
	return result;
}

ssize_t write(int fildes, const void *buf, size_t nbyte) {
	ca_nocipher((void *)buf);
	ssize_t result = libc_write(fildes, buf, nbyte);
	ca_recipher((void *)buf);
	return result;
}

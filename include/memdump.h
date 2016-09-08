#ifndef _MEMDUMP_
#define _MEMDUMP_
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void print_string(void *from, int size) {
	printf("Location of library function %10p\n", print_string);
	for (int i = 0; i < size; i++) {
		printf("%c", *(char *)(from + i));
	}
	printf("\n");
}

static void hex_dump(char *desc, void *addr, int len) {
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char *)addr;
	// Output description if given.
	if (desc != NULL)
		printf("%s:\n", desc);
	if (len == 0) {
		printf("  ZERO LENGTH\n");
		return;
	}
	if (len < 0) {
		printf("  NEGATIVE LENGTH: %i\n", len);
		return;
	}
	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).
		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf("  %s\n", buff);
			// Output the offset.
			printf("  %04x ", i);
		}
		// Now the hex code for the specific character.
		printf(" %02x", pc[i]);
		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}
	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf("   ");
		i++;
	}
	// And print the final ASCII bit.
	printf("  %s\n", buff);
}

void dump_memory(void *address, size_t size, char *path) {
	int fd = 0;
	if ((fd = open(path, O_WRONLY | O_CREAT, 0777)) < 0) {
		perror("Cannot open dump file");
		exit(-1);
	}
	if ((write(fd, address, size)) <= 0) {
		perror("Could not write to file");
		exit(-1);
	}
	close(fd);
}

#endif //_MEMDUMP_

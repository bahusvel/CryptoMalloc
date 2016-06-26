#include <stdio.h>
#include <stdlib.h>

#define TEXT_START_X64 0x400000
#define TEXT_START_X86 0x08048000

char *password = "Denis Lavrov Is Awesome";
extern int etext, edata, end;

void print_string(void *from, int size) {
	for (int i = 0; i < size; i++) {
		printf("%c", *(char *)(from + i));
	}
	printf("\n");
}

void print_bytes(void *from, int size) {
	for (int i = 0; i < size; i++) {
		printf("%02X", *(unsigned char *)(from + i));
		if (i % 4 == 0) {
			printf(" ");
		}
		if (i % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n");
}

void hex_dump(char *desc, void *addr, int len) {
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

int main(int argc, char *argv[]) {
	int local_var = 5; // thats on stack
	char *local_string = "some other string";

	printf("    program text (etext)      %10p\n", &etext);
	printf("    initialized data (edata)  %10p\n", &edata);
	printf("    uninitialized data (end)  %10p\n", &end);
	printf("Location of global variable %10p\n", password);
	printf("Location of local string %10p\n", local_string);
	printf("Location of local variable %10p\n", &local_var);
	printf("Printing from etext:\n");

	hex_dump("from etext", (void *)TEXT_START_X64,
			 (int)&etext - TEXT_START_X64);

	exit(EXIT_SUCCESS);
}

#include <stdio.h>
#include <stdlib.h>

extern int etext, edata, end;

extern char *libstring;
// extern void (*print_string)(void *from, int size);

char *password = "Denis is awesome";

/*
void print_string(void *from, int size) {
	for (int i = 0; i < size; i++) {
		printf("%c", *(char *)(from + i));
	}
	printf("\n");
}
*/

int main() {
	printf("    program text (etext)      %10p\n", &etext);
	printf("    initialized data (edata)  %10p\n", &edata);
	printf("    uninitialized data (end)  %10p\n", &end);
	printf("Location of global variable %10p\n", password);
	printf("Location of library global variable %10p\n", libstring);
	printf("Printing from etext:\n");
	print_string(&etext, 100);

	exit(EXIT_SUCCESS);
}

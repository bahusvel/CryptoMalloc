#include "procstat.h"
#include <stdio.h>
#include <stdlib.h>

extern int etext, edata, end;

char *password = "Denis is awesome";

void print_string(void *from, int size) {
	for (int i = 0; i < size; i++) {
		printf("%c", *(char *)(from + i));
	}
	printf("\n");
}

int main() {
	printf("    program text (etext)      %10p\n", &etext);
	printf("    initialized data (edata)  %10p\n", &edata);
	printf("    uninitialized data (end)  %10p\n", &end);
	printf("Location of global variable %10p\n", password);
	procstat stat;
	get_proc_info(&stat);
	printf("stext %10p\n", stat.startcode);
	printf("etext %10p\n", stat.endcode);
	exit(EXIT_SUCCESS);
}

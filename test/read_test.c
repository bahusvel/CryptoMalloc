#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
	char *buf = malloc(5);
	read(0, buf, 5);
	write(1, buf, 5);
}

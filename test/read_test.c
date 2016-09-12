#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
	char *buf = malloc(5);
	scanf("%s", buf);
	write(1, buf, 5);
}

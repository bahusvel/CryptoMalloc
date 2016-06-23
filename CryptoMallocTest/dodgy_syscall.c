#include <unistd.h>

int main() {
	printf("Its happy\n");
	char *bad_pointer = NULL;
	write(1, bad_pointer, 5);
	return 0;
}

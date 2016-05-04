#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char * argv[]) {
	char *str;
	
	str = (char *) malloc(15);
	strcpy(str, "tutorialspoint");
	printf("String = %s,  Address = %u\n", str, str);

	str = (char *) realloc(str, 25);
	strcat(str, ".com");
	printf("String = %s,  Address = %u\n", str, str);
	
	free(str);
	
	str = calloc(1000, 1);
	int sum = 0;
	for (int i = 0; i < 1000; ++i) {
		sum |= str[i];
	}
	if (sum != 0) {
		printf("At least one array element is non-zero\n");
	}
	
	free(str);
	return(0);
}


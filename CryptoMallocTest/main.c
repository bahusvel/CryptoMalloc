#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

int main(int argc, const char * argv[]) {
	char *str;
	char *orig;
	
	str = (char *) malloc(15);
	strcpy(str, "tutorialspoint");
	printf("String = %s,  Address = %u\n", str, str);
	str = (char *) realloc(str, 25);
	getchar();
	// latency test
	struct timeval start;
	struct timeval stop;
	gettimeofday(&start, NULL);
	char first = str[0];
	gettimeofday(&stop, NULL);
	printf("Decryption took: %d us\n", stop.tv_usec - start.tv_usec);
	//
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


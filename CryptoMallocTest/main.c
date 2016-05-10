#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

int main(int argc, const char * argv[]) {
	char *str;
	char *orig;
	
	// malloc test
	printf("General Malloc & Realloc Test\n");
	str = (char *) malloc(15);
	strcpy(str, "tutorialspoint");
	printf("String = %s,  Address = %u\n", str, str);
	str = (char *) realloc(str, 25);
	strcat(str, ".com");
	printf("String = %s,  Address = %u\n", str, str);
	
	// malloc time
	printf("Malloc Time Test\n");
	struct timeval start;
	struct timeval stop;
	gettimeofday(&start, NULL);
	char *mtime = malloc(4096);
	gettimeofday(&stop, NULL);
	unsigned long stime = 1000000 * start.tv_sec + start.tv_usec;
	unsigned long ftime = 1000000 * stop.tv_sec + stop.tv_usec;
	printf("malloc 1 page took: %ld us, result = %lu\n", ftime - stime, (unsigned long)mtime);
	
	// decrypt latency
	printf("Decrypt Latency\n");
	sleep(2);
	gettimeofday(&start, NULL);
	char first = str[0];
	gettimeofday(&stop, NULL);
	stime = 1000000 * start.tv_sec + start.tv_usec;
	ftime = 1000000 * stop.tv_sec + stop.tv_usec;
	printf("Decryption took: %ld us, result = %c\n", ftime - stime, first);
	
	// free time
	gettimeofday(&start, NULL);
	free(mtime);
	free(str);
	gettimeofday(&stop, NULL);
	stime = 1000000 * start.tv_sec + start.tv_usec;
	ftime = 1000000 * stop.tv_sec + stop.tv_usec;
	printf("free 1 page took: %ld us\n", ftime - stime);
	
	return 0;
}


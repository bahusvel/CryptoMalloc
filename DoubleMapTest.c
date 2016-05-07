#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char *argv[]) {
	const char *path = "/Users/denislavrov/Desktop/dmap.test";
	const char fend = 0;
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
	lseek(fd, 1023, SEEK_SET);
	write(fd, &fend, 1);
	fsync(fd);
	
	void *user = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	void *crypto = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	
	printf("Memory 1: %lu\n", (unsigned long)user);
	printf("Memory 2: %lu\n", (unsigned long)crypto);
	
	*(int*)user = 100;
	printf("User Stored: %d\n", *(int*)crypto);
	mprotect(user, 1024, PROT_READ);
	//*(int*)user = 200; // user cannot write
	*(int*)crypto = 200;
	printf("Oh no someone changed my memory: %d\n", *(int*)user);
	
	close(fd);
}
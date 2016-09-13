#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void xor_cipher(char *message, size_t messagelen, char *key) {
	size_t keylen = strlen(key);
	for (int i = 0; i < messagelen; i++) {
		message[i] = message[i] ^ key[i % keylen];
	}
}

int main(int argc, char **argv) {
	int fd = open("merged.csv", O_RDONLY);
	if (fd < 0) {
		printf("Failed to open database\n");
		return -1;
	}
	struct stat st;
	fstat(fd, &st);
	char *db = malloc(st.st_size);
	if (db == NULL) {
		printf("Failed to allocate memory\n");
		return -1;
	}
	if (read(fd, db, st.st_size) < st.st_size) {
		printf("Failed to read file\n");
		return -1;
	}
	close(fd);
	xor_cipher(db, st.st_size, "bankpassword");
	fd = open("merged.csv.enc", O_WRONLY | O_CREAT | O_TRUNC, 0777);
	if (fd < 0) {
		printf("Failed to open database\n");
		return -1;
	}
	if (write(fd, db, st.st_size) < st.st_size) {
		printf("Failed to writing file\n");
		return -1;
	}
	close(fd);
}

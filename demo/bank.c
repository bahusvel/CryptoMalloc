#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define startsWith(str, prefix) strncmp(prefix, str, strlen(prefix)) == 0

void xor_cipher(char *message, size_t messagelen, char *key) {
	size_t keylen = strlen(key);
	for (int i = 0; i < messagelen; i++) {
		message[i] ^= key[i % keylen];
	}
}

int main(int argc, char **argv) {
	printf("My pid is %d\n", getpid());
	int fd = open("merged.csv.enc", O_RDONLY);
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
	xor_cipher(db, st.st_size, "bankpassword");
	char *lines[100];
	char *line;
	int i = 0;
	while ((line = strsep(&db, "\n"))) {
		lines[i++] = line;
		if (i > 100) {
			break;
		}
	}
	while (1) {
		printf("Enter email address:\n");
		char *input = malloc(1024);
		int n = read(0, input, 1024);
		input[n - 1] = '\0';
		for (int j = 0; j < 100; j++) {
			if (startsWith(lines[j], input)) {
				printf("OK: %s\n", lines[j] + n);
				break;
			}
		}
	}
}

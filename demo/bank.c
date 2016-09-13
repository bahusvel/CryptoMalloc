#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define startsWith(str, prefix) strncmp(prefix, str, strlen(prefix)) == 0

static inline void safe_print(const char *message) {
	write(1, message, strlen(message));
}

int main(int argc, char **argv) {
	printf("My pid is %d\n", getpid());
	int fd = open("merged.csv", O_RDONLY);
	if (fd < 0) {
		safe_print("Failed to open database");
		return -1;
	}
	struct stat st;
	fstat(fd, &st);
	char *db = malloc(st.st_size);
	if (db == NULL) {
		safe_print("Failed to allocate memory");
		return -1;
	}
	if (read(fd, db, st.st_size) < st.st_size) {
		safe_print("Failed to read file");
		return -1;
	}
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
		safe_print("Enter email address:");
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

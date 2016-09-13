#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define startsWith(str, prefix) strncmp(prefix, str, strlen(prefix)) == 0

int main(int argc, char **argv) {
	int fd = open("merged.csv", O_RDONLY);
	if (fd < 0) {
		perror("Failed to open database");
		return -1;
	}
	struct stat st;
	fstat(fd, &st);
	char *db = malloc(st.st_size);
	if (db == NULL) {
		perror("Failed to allocate memory");
		return -1;
	}
	if (read(fd, db, st.st_size) < st.st_size) {
		perror("Failed to read file");
		return -1;
	}
	char lines[100][100];
	char *line;
	int i = 0;
	while ((line = strsep(&db, "\n"))) {
		strcpy(lines[i++], line);
		if (i > 100) {
			break;
		}
	}
	printf("Enter email address:");
	char input[100];
	char ch = 0;
	int j = 0;
	while (1) {
		ch = getc(stdin);
		if (ch == '\n') {
			input[j++] = 0;
			break;
		}
		input[j++] = ch;
	}
	write(1, input, j);
	return 0;
}

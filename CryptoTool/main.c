#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>

void print_ptype(size_t pt) {
	char *s;
#define C(V)                                                                   \
	case PT_##V:                                                               \
		s = #V;                                                                \
		break
	switch (pt) {
		C(NULL);
		C(INTERP);
		C(PHDR);
		C(SUNWBSS);
		C(LOAD);
		C(DYNAMIC);
		C(NOTE);
		C(SHLIB);
		C(TLS);
		C(SUNWSTACK);
	default:
		s = "unknown";
		break;
	}
	printf("%s", s);
#undef C
}

void print_pheader(Elf *elf_file) {
	size_t n;
	GElf_Phdr phdr;
	if (elf_getphdrnum(elf_file, &n) != 0)
		errx(EX_DATAERR, "elf_getphdrnum() failed: %s.", elf_errmsg(-1));
	for (int i = 0; i < n; i++) {
		if (gelf_getphdr(elf_file, i, &phdr) != &phdr)
			errx(EX_SOFTWARE, "getphdr() failed: %s.", elf_errmsg(-1));
		printf("Entry %d:", i);
		print_ptype(phdr.p_type);
		printf(" vaddr: %10p", (void *)phdr.p_vaddr);
		printf(" filesz: %lu", phdr.p_filesz);
		printf(" memsz: %lu", phdr.p_memsz);
		printf(" palign: %d", phdr.p_align);
		if (phdr.p_flags & PF_X)
			printf(" execute");
		if (phdr.p_flags & PF_R)
			printf(" read");
		if (phdr.p_flags & PF_W)
			printf(" write");
		printf("\n");
	}
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("Usage: binencrypt binary\n");
		exit(-1);
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		printf("Elf init failed %s\n", elf_errmsg(-1));
		exit(-1);
	}
	int fd = 0;
	if ((fd = open(argv[1], O_RDWR, 0)) < 0) {
		printf("Failed reading input file");
		exit(-1);
	}
	Elf *elf_file;
	if ((elf_file = elf_begin(fd, ELF_C_RDWR, NULL)) == NULL) {
		printf("Could not read elf file %s\n", elf_errmsg(-1));
		exit(-1);
	}
	if (elf_kind(elf_file) != ELF_K_ELF) {
		printf("This is not an elf executable\n");
		exit(-1);
	}
	GElf_Ehdr ehdr;
	if (gelf_getehdr(elf_file, &ehdr) == NULL) {
		printf("Failed to retrieve elf header %s", elf_errmsg(-1));
		exit(-1);
	}
	if (ehdr.e_type != ET_EXEC) {
		printf("This is not an elf executable\n");
		exit(-1);
	}
	printf("Initial checks complete starting encryption...\n");
	print_pheader(elf_file);

	elf_end(elf_file);
	close(fd);
	return 0;
}

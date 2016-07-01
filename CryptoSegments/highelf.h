#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#define HE_READ_ONLY 0
#define HE_READ_WRITE 1

Elf *load_and_check(char *filepath, int *fd, int write) {
	int open_mode = write ? O_RDWR : O_RDONLY;
	int elf_mode = write ? ELF_C_RDWR : ELF_C_READ;
	if (elf_version(EV_CURRENT) == EV_NONE) {
		printf("Elf init failed %s\n", elf_errmsg(-1));
		exit(-1);
	}
	if ((*fd = open(filepath, open_mode, 0)) < 0) {
		printf("Failed reading input file");
		exit(-1);
	}
	Elf *elf_file;
	if ((elf_file = elf_begin(*fd, elf_mode, NULL)) == NULL) {
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
	return elf_file;
}

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
		printf(" palign: %lu", phdr.p_align);
		if (phdr.p_flags & PF_X)
			printf(" execute");
		if (phdr.p_flags & PF_R)
			printf(" read");
		if (phdr.p_flags & PF_W)
			printf(" write");
		printf("\n");
	}
}

void print_section_header(Elf *elf_file) {
	size_t shstrndx;
	if (elf_getshdrstrndx(elf_file, &shstrndx) != 0) {
		errx(EX_SOFTWARE, "elf_getshdrstrndx() failed: %s.", elf_errmsg(-1));
	}
	Elf_Scn *scn = NULL;
	while ((scn = elf_nextscn(elf_file, scn)) != NULL) {
		char *name = NULL;
		GElf_Shdr shdr;
		if (gelf_getshdr(scn, &shdr) != &shdr)
			errx(EX_SOFTWARE, "getshdr() failed: %s.", elf_errmsg(-1));
		if ((name = elf_strptr(elf_file, shstrndx, shdr.sh_name)) == NULL)
			errx(EX_SOFTWARE, "elf_strptr() failed: %s.", elf_errmsg(-1));
		printf("Section %lu - %s size: %lu, addr: %10p\n", elf_ndxscn(scn),
			   name, shdr.sh_size, (void *)shdr.sh_addr);
	}
}

typedef struct SectionMemory {
	void *location;
	size_t size;
} SectionMemory;

typedef struct EncryptionOffsets {
	void *start_address;
	off_t start;
	off_t size;
} EncryptionOffsets;

Elf_Scn *get_section(Elf *elf_file, const char *section_name) {
	size_t shstrndx;
	if (elf_getshdrstrndx(elf_file, &shstrndx) != 0) {
		errx(EX_SOFTWARE, "elf_getshdrstrndx() failed: %s.", elf_errmsg(-1));
	}
	Elf_Scn *scn = NULL;
	while ((scn = elf_nextscn(elf_file, scn)) != NULL) {
		char *name = NULL;
		GElf_Shdr shdr;
		if (gelf_getshdr(scn, &shdr) != &shdr)
			errx(EX_SOFTWARE, "getshdr() failed: %s.", elf_errmsg(-1));
		if ((name = elf_strptr(elf_file, shstrndx, shdr.sh_name)) == NULL)
			errx(EX_SOFTWARE, "elf_strptr() failed: %s.", elf_errmsg(-1));
		if (strcmp(name, section_name) == 0) {
			return scn;
		}
	}
	return NULL;
}

EncryptionOffsets get_offsets(Elf_Scn *section) {
	GElf_Shdr shdr;
	if (gelf_getshdr(section, &shdr) != &shdr)
		errx(EX_SOFTWARE, "getshdr() failed: %s.", elf_errmsg(-1));
	EncryptionOffsets offsets;
	offsets.start_address = (void *)shdr.sh_addr;
	offsets.start = ((shdr.sh_addr + 4095) & ~4095) - shdr.sh_addr;
	off_t end_addr = shdr.sh_addr + shdr.sh_size;
	offsets.size = (end_addr & ~4095) - shdr.sh_addr;
	return offsets;
}

Elf_Data *read_section_data(Elf_Scn *section) {
	GElf_Shdr shdr;
	if (gelf_getshdr(section, &shdr) != &shdr)
		errx(EX_SOFTWARE, "getshdr() failed: %s.", elf_errmsg(-1));
	Elf_Data *data = NULL;
	// FIXME:0 apparently there can be more than one data descriptor per segment
	if ((data = elf_getdata(section, data)) != NULL) {
		return data;
	}
	return NULL;
}

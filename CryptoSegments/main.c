#include "aes.h"
#include "highelf.h"
#include "memdump.h"
#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

int fd = 0;

static uint8_t AES_KEY[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
							0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
							0x09, 0xcf, 0x4f, 0x3c}; // :)

void decrypt_text_section(Elf *elf_file, char *key) {
	AES128_SetKey(AES_KEY);
	Elf_Scn *text_section = get_section(elf_file, ".text");
	Elf_Data *data = read_section_data(text_section);
	EncryptionOffsets offsets = get_offsets(text_section);
	size_t crypto_size = offsets.end - offsets.start;
	if (crypto_size <= 0) {
		printf("Nothing to decrypt, file's .text section is too small\n");
		exit(-1);
	} else {
		printf("Decrypting %lu bytes from: %p to: %p\n", crypto_size,
			   offsets.start_address + offsets.start,
			   offsets.start_address + offsets.end);
	}
	void *crypto_start = data->d_buf + offsets.start;
	AES128_ECB_decrypt_buffer(crypto_start, crypto_size);
	elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
	if (elf_update(elf_file, ELF_C_WRITE) < 0) {
		errx(EX_SOFTWARE, "elf_update() failed: %s.", elf_errmsg(-1));
	}
}

void encrypt_text_section(Elf *elf_file, char *key) {
	AES128_SetKey(AES_KEY);
	Elf_Scn *text_section = get_section(elf_file, ".text");
	Elf_Data *data = read_section_data(text_section);
	EncryptionOffsets offsets = get_offsets(text_section);
	size_t crypto_size = offsets.end - offsets.start;
	if (crypto_size <= 0) {
		printf("Nothing to encrypt, file's .text section is too small\n");
		exit(-1);
	} else {
		printf("Encrypting %lu byes from: %p to: %p\n", crypto_size,
			   offsets.start_address + offsets.start,
			   offsets.start_address + offsets.end);
	}
	void *crypto_start = data->d_buf + offsets.start;
	AES128_ECB_encrypt_buffer(crypto_start, crypto_size);
	elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
	if (elf_update(elf_file, ELF_C_WRITE) < 0) {
		errx(EX_SOFTWARE, "elf_update() failed: %s.", elf_errmsg(-1));
	}
}

int main(int argc, char *argv[]) {
	if (argc != 3) {
		printf("Usage: binencrypt (encrypt|decrypt) binary\n");
		exit(-1);
	}
	Elf *elf_file = load_and_check(argv[2], &fd, 1);
	elf_flagelf(elf_file, ELF_C_SET, ELF_F_LAYOUT); // ensure consistent layout
	print_section_header(elf_file);
	if (strcmp(argv[1], "encrypt") == 0)
		encrypt_text_section(elf_file, "test");
	else if (strcmp(argv[1], "decrypt") == 0)
		decrypt_text_section(elf_file, "test");
	else if (strcmp(argv[1], "dump") == 0) {
		Elf_Scn *text_section = get_section(elf_file, ".text");
		dump_section(text_section, "text.dump");
	} else
		printf("Unknown verb %s only 'decrypt' and 'encrypt' are allowed\n",
			   argv[1]);
	elf_end(elf_file);
	close(fd);
	return 0;
}

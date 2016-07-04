#define _GNU_SOURCE

#include "aes.h"
#include "bitset.h"
#include "highelf.h"
#include "memdump.h"
#include "procstat.h"
#include "vmstat.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// enables/disables dynamic encryption
#define DYNAMIC_ENCRYPTION 1
// enables/disables dynamic decryption
#define DYNAMIC_DECRYPTION 1

#ifdef DYNAMIC_ENCRYPTION // MUST be enables to support dynamic encryption
#ifndef DYNAMIC_DECRYPTION
#define DYNAMIC_DECRYPTION 1
#endif
#endif

/* NOTE the addresses here are not actual addresses of those segments but
 * their
 * PAGE aligned version, this is done because page access permissions can
 * only
 * be set on page by page basis, and this software relies on them heavily.
*/
typedef struct vm_segment {
	int prot_flags;
	void *start;
	void *end;
	size_t size;
	void *crypto_start;
	unsigned char *stat_bitset;
	int fd;
} vm_segment;

static vm_segment SEG_TEXT = {.prot_flags = PROT_READ | PROT_EXEC, .fd = -1};

// NOTE DATA and BSS are considered the same here
static vm_segment SEG_DATA = {.prot_flags = PROT_READ | PROT_WRITE, .fd = -1};

static inline vm_segment *address_segment(void *address) {
	if (address >= SEG_TEXT.start && address <= SEG_TEXT.end)
		return &SEG_TEXT;
	if (address >= SEG_DATA.start && address <= SEG_DATA.end)
		return &SEG_DATA;
	return NULL;
}

static struct sigaction old_handler;
static pthread_t encryptor_thread;
// I still need a mutex, otherwise the encryptor and decryptor could try and
// touch the same memory, all memory encryption and decryption operations must
// lock this
static pthread_mutex_t page_lock = PTHREAD_MUTEX_INITIALIZER;
unsigned int PAGE_SIZE = 0;
static uint8_t AES_KEY[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
							0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
							0x09, 0xcf, 0x4f, 0x3c}; // :)

#ifdef DYNAMIC_DECRYPTION
static void decryptor(int signum, siginfo_t *info, void *context) {
	void *address = info->si_addr;
	printf("It tried to access %p\n", address);
	if (address == NULL)
		goto segfault;
	vm_segment *this_segment = address_segment(address);
	if (this_segment == NULL)
		goto segfault;
	// align to page boundary
	address = (void *)((unsigned long)address & ~((unsigned long)4095));
	void *crypto_addr =
		address - this_segment->start + this_segment->crypto_start;
	unsigned int stat_bit = (address - this_segment->start) / 4096;
	pthread_mutex_lock(&page_lock);
	if (!BITTEST(this_segment->stat_bitset, stat_bit)) {
		printf("%p is not encrypted!\n", address);
		pthread_mutex_unlock(&page_lock);
		goto segfault;
	}
	AES128_ECB_decrypt_buffer(crypto_addr, PAGE_SIZE);
	mprotect(address, PAGE_SIZE, this_segment->prot_flags);
	BITCLEAR(this_segment->stat_bitset, stat_bit);
	pthread_mutex_unlock(&page_lock);
	// printf("Decrypted!\n");
	return;
segfault:
	printf("Real Seg Fault Happened :(\n");
	old_handler.sa_sigaction(signum, info, context);
	return;
}
#endif

#ifdef DYNAMIC_ENCRYPTION
static void *encryptor(void *ptr) {

	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGSEGV);
	// this will block sigsegv on this thread, so ensure code from here on is
	// correct
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	printf("Thread running\n");
	while (1) {
		pthread_mutex_lock(&page_lock);
		// write(1, "locked\n", 7);
		void *crypto_address = SEG_TEXT.crypto_start;
		void *real_address = SEG_TEXT.start;
		unsigned int stat_bit = 0;
		for (; real_address < SEG_TEXT.end; crypto_address += PAGE_SIZE,
											real_address += PAGE_SIZE,
											stat_bit++) {
			if (!BITTEST(SEG_TEXT.stat_bitset, stat_bit)) {
				mprotect(real_address, PAGE_SIZE, PROT_NONE);
				AES128_ECB_encrypt_buffer(crypto_address, PAGE_SIZE);
				BITSET(SEG_TEXT.stat_bitset, stat_bit);
				printf("Encrypted! %10p\n", real_address);
			}
		}
		// write(1, "unlocking\n", 10);
		pthread_mutex_unlock(&page_lock);
		// write(1, "unlocked\n", 9);
		usleep(1000000);
	}
	return NULL;
}
#endif

static void remap_segment(vm_segment *segment) {
	static int segment_count = 0;
	char path[PATH_MAX];
	sprintf(path, "/%d_segment%d.mem", getpid(), segment_count++);
	segment->fd = shm_open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
	if (segment->fd < 0) {
		perror("segment remap shm_open");
		exit(-1);
	}
	if (ftruncate(segment->fd, segment->size) < 0) {
		perror("segment remap ftruncate");
		exit(-1);
	}
	segment->crypto_start =
		mmap(NULL, segment->size, PROT_READ | PROT_WRITE | PROT_EXEC,
			 MAP_SHARED, segment->fd, 0);
	if (segment->crypto_start == MAP_FAILED) {
		perror("segment remap mmap_crypto");
		exit(-1);
	}
	memcpy(segment->crypto_start, segment->start, segment->size);
	munmap(segment->start, segment->size);
	void *new_mmap = mmap(segment->start, segment->size, segment->prot_flags,
						  MAP_SHARED, segment->fd, 0);
	if (new_mmap != segment->start) {
		perror("segment remap mmap_clear");
		exit(-1);
	}
}

// TODO unlink all the shared memory files
static void fini_segments() {}

static void init_segments() {
	int fd = 0;
	Elf *elf_file = load_and_check("/proc/self/exe", &fd, 0);

	Elf_Scn *text_section = get_section(elf_file, ".text");
	EncryptionOffsets offsets = get_offsets(text_section);
	SEG_TEXT.start = offsets.start_address + offsets.start;
	SEG_TEXT.end = offsets.start_address + offsets.end;
	SEG_TEXT.size = SEG_TEXT.end - SEG_TEXT.start;
	SEG_TEXT.stat_bitset = malloc(BITNSLOTS(SEG_TEXT.size / 4096));
	remap_segment(&SEG_TEXT);
	printf("start text (etext)      %p\n", SEG_TEXT.start);
	printf("end text (etext)      %p\n", SEG_TEXT.end);

	elf_end(elf_file);
	close(fd);
}

#ifndef DYNAMIC_DECRYPTION
static void decrypt_segment(vm_segment *segment) {
	printf("Decryption size is: %lu\n", segment->size);
	mprotect(segment->start, segment->size, PROT_READ | PROT_WRITE);
	AES128_ECB_decrypt_buffer(segment->start, segment->size);
	mprotect(segment->start, segment->size, segment->prot_flags);
}
#endif

__attribute__((constructor)) static void segments_ctor() {
	PAGE_SIZE = sysconf(_SC_PAGESIZE);
	AES128_SetKey(AES_KEY);
	init_segments();

#ifndef DYNAMIC_DECRYPTION
	decrypt_segment(&SEG_TEXT);
#endif

#ifdef DYNAMIC_DECRYPTION
	// FIXME change access flags on encrypted text segment, this probably can be
	// done in the static encryptor itself actually
	mprotect(SEG_TEXT.start, SEG_TEXT.size, PROT_NONE);
	// set all bits as encrypted
	memset(SEG_TEXT.stat_bitset, ~0, BITNSLOTS(SEG_TEXT.size / 4096));
	// setting up signal handler
	static struct sigaction sa;
	sa.sa_sigaction = decryptor;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGSEGV);
	sa.sa_flags = SA_SIGINFO | SA_RESTART;

	if (sigaction(SIGSEGV, &sa, &old_handler) < 0) {
		perror("Signal Handler Installation Failed:");
		exit(EXIT_FAILURE);
	}
#endif

#ifdef DYNAMIC_ENCRYPTION
	int iret = pthread_create(&encryptor_thread, NULL, encryptor, NULL);
	if (iret) {
		printf("Error - pthread_create() return code: %d\n", iret);
		exit(EXIT_FAILURE);
	}
#endif
}

__attribute__((destructor)) static void segments_dtor() {}

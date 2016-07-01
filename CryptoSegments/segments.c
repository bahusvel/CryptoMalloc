#define _GNU_SOURCE

#include "aes.h"
#include "highelf.h"
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

/* NOTE the addresses here are not actual addresses of those segments but their
 * PAGE aligned version, this is done because page access permissions can only
 * be set on page by page basis, and this software relies on them heavily.
*/
typedef struct vm_segment {
	int prot_flags;
	void *start;
	void *end;
} vm_segment;

static vm_segment SEG_TEXT = {
	.prot_flags = PROT_READ | PROT_EXEC, .start = NULL, .end = NULL};

// NOTE DATA and BSS are considered the same here
static vm_segment SEG_DATA = {
	.prot_flags = PROT_READ | PROT_WRITE, .start = NULL, .end = NULL};

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
	pthread_mutex_lock(&page_lock);
	mprotect(address, PAGE_SIZE, PROT_READ | PROT_WRITE);
	for (size_t i = 0; i < PAGE_SIZE; i += 16) {
		AES128_ECB_decrypt_inplace(address + i);
	}
	mprotect(address, PAGE_SIZE, this_segment->prot_flags);
	pthread_mutex_unlock(&page_lock);
	printf("Decrypted!\n");
	return;
segfault:
	printf("Real Seg Fault Happened :(\n");
	old_handler.sa_sigaction(signum, info, context);
	return;
}

static void *encryptor(void *ptr) {

	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGSEGV);
	// this will block sigsegv on this thread, so ensure code from here on is
	// correct
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	printf("Thread running\n");
	while (1) {
		// NOTE the condition of this loop dictates the end encryption address
		pthread_mutex_lock(&page_lock);
		// write(1, "locked\n", 7);
		for (void *address = SEG_TEXT.start; address < SEG_TEXT.end;
			 address += PAGE_SIZE) {
			int vm_stat = check_read(address);
			if (vm_stat == PROT_READ) {
				mprotect(address, PAGE_SIZE, PROT_READ | PROT_WRITE);
				for (size_t i = 0; i < PAGE_SIZE; i += 16) {
					AES128_ECB_encrypt_inplace(address + i);
				}
				mprotect(address, PAGE_SIZE, PROT_NONE);
				// printf("Encrypted! %10p\n", address);
			}
		}
		// write(1, "unlocking\n", 10);
		pthread_mutex_unlock(&page_lock);
		// write(1, "unlocked\n", 9);
		usleep(1000000);
	}
	return NULL;
}

__attribute__((constructor)) static void segments_ctor() {
	PAGE_SIZE = sysconf(_SC_PAGESIZE);
	AES128_SetKey(AES_KEY);

	// initialize the segment addresses since they are not available at compile
	// time
	int fd = 0;
	Elf *elf_file = load_and_check("/proc/self/exe", &fd, 0);
	Elf_Scn *text_section = get_section(elf_file, ".text");
	EncryptionOffsets offsets = get_offsets(text_section);
	SEG_TEXT.start = offsets.start_address + offsets.start;
	SEG_TEXT.end = offsets.start_address + offsets.size;
	elf_end(elf_file);
	close(fd);

	printf("start text (etext)      %p\n", SEG_TEXT.start);
	printf("end text (etext)      %p\n", SEG_TEXT.end);

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
	/* Dont start dynamic encryption for now
	int iret = pthread_create(&encryptor_thread, NULL, encryptor, NULL);
	if (iret) {
		printf("Error - pthread_create() return code: %d\n", iret);
		exit(EXIT_FAILURE);
	}
	*/
}

__attribute__((destructor)) static void segments_dtor() {}

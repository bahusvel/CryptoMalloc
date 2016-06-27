#define _GNU_SOURCE

#include "aes.h"
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

static void *stext = 0;
static void *etext = 0;
extern int edata, end;

#define TEXT_START_X64 0x400000
#define TEXT_START_X86 0x08048000

#if __x86_64__
#define TEXT_START TEXT_START_X64
#endif
#if __i386__
#define TEXT_START TEXT_START_X86
#endif

#define IN_TEXT(address)                                                       \
	(address >= (void *)TEXT_START) && (address < etext) ? 1 : 0
#define IN_DATA(address)                                                       \
	(address >= etext) && (address < (void *)&edata) ? 1 : 0
#define IN_BSS(address)                                                        \
	(address >= (void *)&edata) && (address < (void *)&end) ? 1 : 0

typedef struct vm_segment {
	int prot_flags;
	void *start;
	void *end;
} vm_segment;

static vm_segment SEG_TEXT = {.prot_flags = PROT_READ | PROT_EXEC,
							  .start = (void *)TEXT_START,
							  .end = NULL};
static vm_segment SEG_DATA = {
	.prot_flags = PROT_READ | PROT_WRITE, .start = NULL, .end = NULL};
static vm_segment SEG_BSS = {
	.prot_flags = PROT_READ | PROT_WRITE, .start = NULL, .end = NULL};

static inline vm_segment *address_segment(void *address) {
	if (IN_TEXT(address))
		return &SEG_TEXT;
	if (IN_DATA(address))
		return &SEG_DATA;
	if (IN_BSS(address)) {
		return &SEG_BSS;
	}
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
	if (address == NULL)
		goto segfault;
	if (!IN_TEXT(address))
		goto segfault;
	// align to page boundary
	printf("Address %10p\n", address);
	address = (void *)((unsigned long)address & ~((unsigned long)4095));
	printf("Aligned %10p\n", address);
	pthread_mutex_lock(&page_lock);
	mprotect(address, PAGE_SIZE, PROT_READ | PROT_WRITE);
	for (size_t i = 0; i < PAGE_SIZE; i += 16) {
		AES128_ECB_decrypt_inplace(address + i);
	}
	mprotect(address, PAGE_SIZE, PROT_READ | PROT_EXEC);
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
		for (void *address = (void *)TEXT_START; address < etext;
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
		pthread_mutex_unlock(&page_lock);
		usleep(1000000);
	}
	return NULL;
}

__attribute__((constructor)) static void segments_ctor() {
	PAGE_SIZE = sysconf(_SC_PAGESIZE);
	AES128_SetKey(AES_KEY);

	procstat stats;
	if (get_proc_info(&stats)) {
		perror("Proc Stats");
		exit(-1);
	}
	stext = (void *)stats.startcode;
	etext = (void *)stats.endcode;
	printf("    program text (etext)      %10p\n", etext);
	printf("    initialized data (edata)  %10p\n", &edata);
	printf("    uninitialized data (end)  %10p\n", &end);
	// initialize the segment addresses since they are not available at compile
	// time

	SEG_TEXT.end = etext;
	SEG_DATA.start = etext;
	SEG_DATA.end = &edata;
	SEG_BSS.start = &edata;
	SEG_BSS.end = &end;

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

	int iret = pthread_create(&encryptor_thread, NULL, encryptor, NULL);
	if (iret) {
		printf("Error - pthread_create() return code: %d\n", iret);
		exit(EXIT_FAILURE);
	}
}

__attribute__((destructor)) static void segments_dtor() {}

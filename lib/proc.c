#include "bitset.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define ALIGN_UP(val, n) (val + (n - 1)) & ~(n - 1)
#define ALIGN_DOWN(val, n) val & ~(n - 1)
#define PAGE_SIZE 4096

static uint8_t AES_KEY[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
							0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
							0x09, 0xcf, 0x4f, 0x3c}; // :)

typedef struct map_entry {
	void *start;
	void *end;
	int flags;
	void *offset;
	char dev[6];
	unsigned long inode;
	char path[PATH_MAX];
	struct map_entry *next;
} map_entry;

typedef struct crypto_region {
	map_entry *proc_entry;
	unsigned char *status_bitset;
} crypto_region;

void *malloc_offheap(size_t size) {
	void *addr = mmap(NULL, ALIGN_UP(size, PAGE_SIZE), PROT_READ | PROT_WRITE,
					  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (addr == MAP_FAILED) {
		return NULL;
	}
	return addr;
}

void free_offheap(void *ptr, size_t size) {
	munmap(ptr, ALIGN_UP(size, PAGE_SIZE));
}

map_entry *parse_maps() {
	FILE *maps = fopen("/proc/self/maps", "r");
	map_entry *head = malloc_offheap(sizeof(map_entry));
	map_entry *entry = head;
	char flags[5];
	while (1) {
		int tokens = fscanf(maps, "%p-%p %s %p %s %lu %s", &entry->start,
							&entry->end, flags, &entry->offset, entry->dev,
							&entry->inode, entry->path);
		if (tokens != 7) {
			break;
		}
		if (flags[0] == 'r')
			entry->flags |= PROT_READ;
		if (flags[1] == 'w')
			entry->flags |= PROT_WRITE;
		if (flags[2] == 'x')
			entry->flags |= PROT_EXEC;
		entry->next = malloc_offheap(sizeof(map_entry));
		entry = entry->next;
	}
	free(entry->next);
	entry->next = NULL;
	return head;
}

crypto_region find_data(map_entry *proc_maps) {
	char *this_process = proc_maps->path;
	crypto_region region;
	for (map_entry *entry = proc_maps; entry != NULL; entry = entry->next) {
		if (entry->flags & PROT_WRITE &&
			strcmp(this_process, entry->path) == 0) {
			region.proc_entry = entry;
			size_t size_in_pages = (entry->end - entry->start) / PAGE_SIZE;
			region.status_bitset = malloc_offheap(BITNSLOTS(size_in_pages));
			memset(region.status_bitset, 0, BITNSLOTS(size_in_pages));
		}
	}
	return region;
}

static void decryptor(int signum, siginfo_t *info, void *context) {
	void *address = info->si_addr;
	// printf("It tried to access %p\n", address);
	if (address == NULL)
		goto segfault;
	vm_segment *this_segment = address_segment(address);
	if (this_segment == NULL)
		goto segfault;
	// align to page boundary
	address = ALIGN_DOWN(address, PAGE_SIZE);
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
				// printf("Encrypted! %10p\n", real_address);
			}
		}
		// write(1, "unlocking\n", 10);
		pthread_mutex_unlock(&page_lock);
		// write(1, "unlocked\n", 9);
		usleep(1000000);
	}
	return NULL;
}

__attribute__((constructor)) static void crypto_malloc_ctor() {
	AES128_SetKey(AES_KEY);
	init_segments();

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

int main() {
	map_entry *proc_maps = parse_maps();
	crypto_region data = find_data(proc_maps);
	printf("data %p-%p\n", data.proc_entry->start, data.proc_entry->end);
}

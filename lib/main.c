//
//  main.c
//  CryptoMalloc
//
//  Created by denis lavrov on 3/05/16.
//  Copyright © 2016 Denis Lavrov. All rights reserved.
//

#define _GNU_SOURCE

#include "aes.h"
#include "camalloc.h"
#include "list.h"
#include "lock.h"
#include "shims.h"

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define CRYPTO_NOCIPHER 0x01
#define CRYPTO_CLEAR 0x02
#define CRYPTO_CIPHER 0x04
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define ALIGN_UP(val, n) (val + (n - 1)) & ~(n - 1)
#define ALIGN_DOWN(val, n) val & ~(n - 1)

static char PID_PATH[PATH_MAX];
static int PAGE_SIZE;
static cor_map mem_map = {NULL};
static cor_map free_map = {NULL};
static int fd = -1;
static off_t crypto_mem_break = 0;
static struct sigaction old_handler;
static pthread_t encryptor_thread;

/*
MUST READ !!! DO NOT WRITE ANY CODE UNTIL YOU READ THIS !!!
This mutex is crucial, it locks access to cor_map and all of its nodes, you must
lock it if you are making decisions based on some infomation in one of the
cor_map_nodes as it may change at any time, you must perform those checks only
after you locked this. Exceptions to this rule are very rare, hence always lock
unless you are sure.
*/
static cor_lock cor_map_lock;

static uint8_t AES_KEY[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
							0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
							0x09, 0xcf, 0x4f, 0x3c}; // :)

static inline void encrypt_node(cor_map_node *np) {
	mprotect(np->key, np->alloc_size, PROT_NONE);
	AES128_ECB_encrypt_buffer(np->cryptoaddr, np->crypto_size);
	np->flags = CRYPTO_CIPHER;
}

static inline void decrypt_node(cor_map_node *np) {
	AES128_ECB_decrypt_buffer(np->cryptoaddr, np->crypto_size);
	mprotect(np->key, np->alloc_size, PROT_READ | PROT_WRITE | PROT_EXEC);
	np->flags = CRYPTO_CLEAR;
}

void ca_nocipher(void *address) {
	if (address == NULL)
		return;
	cor_map_node *np;
	lock_lock(&cor_map_lock);
	if ((np = cor_map_range(&mem_map, address)) != NULL &&
		(np->flags != CRYPTO_NOCIPHER)) {
		if (np->flags == CRYPTO_CIPHER) {
			decrypt_node(np);
		}
		np->flags = CRYPTO_NOCIPHER;
	}
	lock_unlock(&cor_map_lock);
}

void ca_recipher(void *address) {
	if (address == NULL)
		return;
	cor_map_node *np;
	if ((np = cor_map_range(&mem_map, address)) != NULL &&
		(np->flags == CRYPTO_NOCIPHER)) {
		np->flags = CRYPTO_CLEAR;
	}
}

void ca_encrypt(void *address) {
	if (address == NULL)
		return;
	cor_map_node *np;
	lock_lock(&cor_map_lock);
	if ((np = cor_map_range(&mem_map, address)) != NULL &&
		np->flags != CRYPTO_CIPHER) {
		encrypt_node(np);
	}
	lock_unlock(&cor_map_lock);
}

void ca_decrypt(void *address) {
	if (address == NULL)
		return;
	cor_map_node *np;
	lock_lock(&cor_map_lock);
	if ((np = cor_map_range(&mem_map, address)) != NULL &&
		(np->flags == CRYPTO_CIPHER)) {
		decrypt_node(np);
	}
	lock_unlock(&cor_map_lock);
}

static void decryptor(int signum, siginfo_t *info, void *context) {
	void *address = info->si_addr;
	if (address == NULL)
		goto segfault;
	cor_map_node *np;
	lock_lock(&cor_map_lock);
	if ((np = cor_map_range(&mem_map, address)) != NULL) {
		decrypt_node(np);
		lock_unlock(&cor_map_lock);
		return;
	}
	lock_unlock(&cor_map_lock);
segfault:
	// if stdin and stdout buffers are encrypted this might be bad...
	safe_print("Real Seg Fault Happened :(\n");
	old_handler.sa_sigaction(signum, info, context);
	return;
}

static void *encryptor(void *ptr) {
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGSEGV);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	cor_map *map = &mem_map;
	cor_map_node *np;
	while (1) {
		lock_lock(&cor_map_lock);
		COR_MAP_FOREACH(map, np) {
			if (np->flags == CRYPTO_CLEAR) {
				encrypt_node(np);
			}
		}
		lock_unlock(&cor_map_lock);
		usleep(1000 * 1000);
	}
	return NULL;
}

static inline void *symbol_from_lib(void *dlhandle, const char *symbol_name) {
	// locate libc funcions (potentially through libc file)
	void *symbol = dlsym(dlhandle, symbol_name);
	if (symbol == NULL) {
		printf("Failed to fetch %s\n", symbol_name);
		exit(-1);
	}
	return symbol;
}

__attribute__((constructor)) static void crypto_malloc_ctor() {

	if (sysconf(_SC_NPROCESSORS_ONLN) > 1) {
		lock_init(&cor_map_lock, LOCK_SPIN);
	} else {
		lock_init(&cor_map_lock, LOCK_MUTEX);
	}

	PAGE_SIZE = getpagesize();
	AES128_SetKey(AES_KEY);

#ifdef __APPLE__
	__libc_malloc = dlsym(RTLD_NEXT, "malloc");
	__libc_free = dlsym(RTLD_NEXT, "free");
#endif

	sprintf(PID_PATH, "/%d.mem", getpid());
	fd = shm_open(PID_PATH, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
	if (fd < 0) {
		safe_print("Open");
		abort();
	}

#define X(n) libc_##n = symbol_from_lib(RTLD_NEXT, #n);
	OPLIST
#undef X

	// setting up signal handler
	static struct sigaction sa;
	sa.sa_sigaction = decryptor;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGSEGV);
	sa.sa_flags = SA_SIGINFO | SA_RESTART;

	if (sigaction(SIGSEGV, &sa, &old_handler) < 0) {
		safe_print("Signal Handler Installation Failed:");
		abort();
	}

	int iret = pthread_create(&encryptor_thread, NULL, encryptor, NULL);
	if (iret) {
		safe_print("Error - pthread_create()");
		exit(EXIT_FAILURE);
	}
}

__attribute__((destructor)) static void crypto_malloc_dtor() {
	close(fd);
	shm_unlink(PID_PATH);
}

void *malloc(size_t size) {
	// safe_print("Malloc called\n");
	if (size == 0)
		return NULL;
	size_t crypto_size = ALIGN_UP(size, 16);
	size = ALIGN_UP(size, PAGE_SIZE); // must be page aligned for offset
	cor_map_node *fit_node = NULL;

	lock_lock(&cor_map_lock);

	// try to reuse, freed memory
	if ((fit_node = cor_map_find_fit(&free_map, size)) != NULL) {
		cor_map_delete(&free_map, fit_node->key);
		fit_node->flags = CRYPTO_CLEAR;
		cor_map_set(&mem_map, fit_node);
		goto success;
	}
	// otherwise go ahead and allocate some more
	off_t foffset = crypto_mem_break;
	crypto_mem_break += size;

	if (ftruncate(fd, crypto_mem_break) < 0) {
		safe_print("ftruncate");
		goto failure;
	}

	void *user_mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
						  MAP_SHARED, fd, foffset);
	void *crypto_mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
							MAP_SHARED, fd, foffset);

	if (user_mem != MAP_FAILED) {
		fit_node = __libc_malloc(sizeof(cor_map_node));
		fit_node->key = user_mem;
		fit_node->cryptoaddr = crypto_mem;
		fit_node->alloc_size = size;
		fit_node->crypto_size = crypto_size;
		fit_node->flags = CRYPTO_CLEAR;
		cor_map_set(&mem_map, fit_node);
		goto success;
	} else {
		safe_print("mmap");
		errno = ENOMEM;
		goto failure;
	}

failure:
	lock_unlock(&cor_map_lock);
	return NULL;
success:
	lock_unlock(&cor_map_lock);
	return fit_node->key;
}

void free(void *ptr) {
	if (ptr == NULL)
		return;
	lock_lock(&cor_map_lock);
	static cor_map_node *previous = NULL;
	if (previous != NULL) {
		if (previous->flags & CRYPTO_CLEAR) {
			// zero out the memory before releasing if it is clear
			memset(previous->key, 0, previous->crypto_size);
		}
		previous->next = NULL;
		cor_map_set(&free_map, previous);
		previous = NULL;
	}

	if ((previous = cor_map_delete(&mem_map, ptr)) == NULL) {
		// It really should never go here, but its left as a precaution
		safe_print("free: Forreign pointer\n");
	}
	lock_unlock(&cor_map_lock);
}

// FIXME:10 Use a more sophisticated realloc, for better performance
void *realloc(void *ptr, size_t size) {
	if (ptr == NULL)
		return malloc(size);
	if (size == 0) {
		free(ptr);
		return NULL;
	}
	cor_map_node *node;
	void *new_addr = NULL;
	if ((node = cor_map_get(&mem_map, ptr)) != NULL) {
		new_addr = malloc(size);
		if (new_addr == NULL) {
			safe_print("MALLOC RETURNED NULL");
			return NULL;
		}
		memcpy(new_addr, ptr,
			   node->alloc_size < size ? node->alloc_size : size);
		free(ptr);
		return new_addr;
	}
	// It really should never go here, but its left as a precaution
	safe_print("realloc: Forreign pointer\n");
	return NULL;
}

void *calloc(size_t count, size_t size) {
	if (count == 0 || size == 0)
		return NULL;
	size_t fsize = count * size;
	void *result = malloc(fsize);

	lock_lock(&cor_map_lock);
	assert(result != NULL);

	memset(result, 0, fsize);
	lock_unlock(&cor_map_lock);

	return result;
}

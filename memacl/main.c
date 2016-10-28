//
//  main.c
//  CryptoMalloc
//
//  Created by denis lavrov on 3/05/16.
//  Copyright © 2016 Denis Lavrov. All rights reserved.
//

#define _GNU_SOURCE

#include "list.h"

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
#include <ucontext.h>
#include <unistd.h>

#define CRYPTO_NOCIPHER 0x01
#define CRYPTO_CLEAR 0x02
#define CRYPTO_CIPHER 0x04
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define ALIGN_UP(val, n) (val + (n - 1)) & ~(n - 1)
#define ALIGN_DOWN(val, n) val & ~(n - 1)

static int PAGE_SIZE;
static cor_map mem_map = {NULL};
static struct sigaction old_handler;
static pthread_t encryptor_thread;

static pthread_mutex_t mymutex = PTHREAD_MUTEX_INITIALIZER;

static inline int lib_for_symbol(void *symbol, Dl_info *info) {
	if (dladdr(symbol, info) == 0) {
		return -1;
	}
	return 0;
}

static void decryptor(int signum, siginfo_t *info, void *context) {
	void *address = info->si_addr;
	if (address == NULL)
		goto segfault;
	cor_map_node *np;
	pthread_mutex_lock(&mymutex);
	if ((np = cor_map_range(&mem_map, address)) != NULL) {
		ucontext_t *user_context = (ucontext_t *)context;
		void *ip = (void *)user_context->uc_mcontext.gregs[REG_RIP];
		Dl_info info;
		if (!lib_for_symbol(ip, &info)) {
			printf("Access to %p from %s-%s (start: %p, pos: %p)\n", address,
				   info.dli_fname, info.dli_sname, info.dli_saddr, ip);
		} else {
			printf("Access to %p from %p\n", address, ip);
		}
		pthread_mutex_unlock(&mymutex);
		return;
	}
	pthread_mutex_unlock(&mymutex);
segfault:
	// if stdin and stdout buffers are encrypted this might be bad...
	printf("Real Seg Fault Happened :(\n");
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
		pthread_mutex_lock(&mymutex);
		COR_MAP_FOREACH(map, np) {
			if (np->flags == CRYPTO_CLEAR) {
			}
		}
		pthread_mutex_unlock(&mymutex);
		usleep(1000 * 1000);
	}
	return NULL;
}

__attribute__((constructor)) static void crypto_malloc_ctor() {
	PAGE_SIZE = getpagesize();

	// setting up signal handler
	static struct sigaction sa;
	sa.sa_sigaction = decryptor;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGSEGV);
	sa.sa_flags = SA_SIGINFO | SA_RESTART;

	if (sigaction(SIGSEGV, &sa, &old_handler) < 0) {
		printf("Signal Handler Installation Failed:");
		abort();
	}

	int iret = pthread_create(&encryptor_thread, NULL, encryptor, NULL);
	if (iret) {
		printf("Error - pthread_create()");
		exit(EXIT_FAILURE);
	}
}

__attribute__((destructor)) static void crypto_malloc_dtor() {}

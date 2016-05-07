//
//  main.c
//  CryptoMalloc
//
//  Created by denis lavrov on 3/05/16.
//  Copyright © 2016 Denis Lavrov. All rights reserved.
//

#define _GNU_SOURCE

#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static pthread_mutex_t mymutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct cor_map_node {
    void			*key;
	void			*cryptoaddr;
	size_t			alloc_size;
    struct cor_map_node *next;
} cor_map_node;

typedef struct cor_map{
    cor_map_node *first;
} cor_map;

static cor_map_node *cor_map_delete(cor_map* map, void* key){
	cor_map_node *pnp;
	cor_map_node *np;
	for (np = map->first, pnp = map->first; np != NULL; pnp = np, np = np->next){
		if (np->key == key) {
			if (np == map->first){
				map->first = np->next;
			} else {
				pnp->next = np->next;
			}
			return np;
		}
	}
	return NULL;
}

static cor_map_node *cor_map_get(cor_map* map, void* key){
	cor_map_node *np;
	for (np = map->first; np != NULL; np = np->next){
		if (np->key == key) {
			return np;
		}
	}
	return NULL;
}

static inline void cor_map_set(cor_map* map, cor_map_node *node){ // can be inlined
	node->next = map->first;
	map->first = node;
}


static char *CRYPTO_PATH = "/Users/denislavrov/Desktop/RAM/";
static char PID_PATH[PATH_MAX];
static int PAGE_SIZE;
static volatile unsigned long __crypto_allocid = 0;
static cor_map mem_map = {NULL};
static const char fend = 0;
static int fd = -1;
static struct sigaction old_handler;
static pthread_t encryptor_thread;

static void decryptor(int signum, siginfo_t *info, void *context){
	// code here must be heavily optimised, page fault code !!!
	void *address = info->si_addr;
	if (address == NULL) goto segfault;
	cor_map_node *np;
	pthread_mutex_lock(&mymutex);
	for (np = mem_map.first; np != NULL; np = np->next){
		if (np->key <= address && address <= (np->key + np->alloc_size)){
			goto decrypt;
		}
	}
	pthread_mutex_unlock(&mymutex);
	goto segfault;
decrypt:
	//printf("Decrypting your ram\n");
	mprotect(np->key, np->alloc_size, PROT_READ | PROT_WRITE);
	pthread_mutex_unlock(&mymutex);
	return;
segfault:
	printf("Real Seg Fault Happened :(\n");
	old_handler.sa_sigaction(signum, info, context);
	return;
}

static void encryptor(void *ptr){
	while (1) {
		//printf("Encryptor is spinning\n");
		cor_map_node *np;
		pthread_mutex_lock(&mymutex);
		for (np = mem_map.first; np != NULL; np = np->next){
			mprotect(np->key, np->alloc_size, PROT_NONE);
		}
		pthread_mutex_unlock(&mymutex);
		usleep(1000000);
	}
}

__attribute__((constructor))
static void crypto_malloc_ctor(){
	PAGE_SIZE = getpagesize();
	// change this to temp
	char *envPath = getenv("CRYPTO_PATH");
	if (envPath != NULL) {
		CRYPTO_PATH = envPath;
	}
	
	sprintf(PID_PATH, "%s%d.mem", CRYPTO_PATH, getpid());
	fd = open(PID_PATH, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
	if (fd < 0) {
		perror("Open");
		abort();
	}
	
	// setting up signal handler
	static struct sigaction sa;
	sa.sa_sigaction = decryptor;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGSEGV);
	sa.sa_flags = SA_SIGINFO;
	
	if (sigaction(SIGSEGV, &sa, &old_handler) < 0){
		perror("Signal Handler Installation Failed:");
		abort();
	}
	
	int iret = pthread_create(&encryptor_thread, NULL, encryptor, NULL);
	if(iret){
		printf("Error - pthread_create() return code: %d\n",iret);
		exit(EXIT_FAILURE);
	}

}


__attribute__((destructor))
static void crypto_malloc_dtor(){
	close(fd);
	unlink(PID_PATH);
}


void *malloc(size_t size){
	if (size == 0) return NULL;
	// TODO: may need to check if the right segfault handler is set
	size = size + sizeof(cor_map_node);
	size = (size + 4095) & ~0xFFF; // must be page aligned for offset
	pthread_mutex_lock(&mymutex);
    off_t new_offset = lseek(fd, size - 1, SEEK_END);
	if (new_offset < 0){
		perror("Could not seek");
		return NULL;
	}
	off_t foffset = new_offset - (size - 1);
    write(fd, &fend, 1);
    fsync(fd);
	
    void *user_mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd, foffset);
	void *crypto_mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd, foffset);
	
    if (user_mem != MAP_FAILED) {
		cor_map_node *head_node = crypto_mem;
		head_node->key = user_mem;
		head_node->cryptoaddr = crypto_mem;
		head_node->alloc_size = size;
        cor_map_set(&mem_map, head_node);
		pthread_mutex_unlock(&mymutex);
        return user_mem + sizeof(cor_map_node);
    } else {
		perror("mmap");
		errno = ENOMEM;
		pthread_mutex_unlock(&mymutex);
        return NULL;
    }
}

void free(void *ptr){
	if (ptr == NULL) return;
	ptr -= sizeof(cor_map_node);
	pthread_mutex_lock(&mymutex);
	static cor_map_node *previous = NULL;
	if (previous != NULL) {
		munmap(previous->key, previous->alloc_size);
		munmap(previous->cryptoaddr, previous->alloc_size);
		previous = NULL;
	}
    cor_map_node *node;
	if ((node = cor_map_delete(&mem_map, ptr)) != NULL){
		previous = node;
	} else {
		// It really should never go here, but its left as a precaution
		printf("LIBC FREE\n");
	}
	pthread_mutex_unlock(&mymutex);
}

// TODO: Use a more sophisticated realloc, for better performance
void *realloc(void *ptr, size_t size){
	//printf("IT CALLED REALLOC\n");
	if (ptr == NULL) return malloc(size);
	if (size == 0){
		free(ptr);
		return NULL;
	}
	void *user_ptr = ptr - sizeof(cor_map_node);
	cor_map_node *node;
	void *new = NULL;
	if ((node = cor_map_get(&mem_map, user_ptr)) != NULL){
		size_t node_size = node->alloc_size - sizeof(cor_map_node);
		new = malloc(size);
		if (new == NULL) {
			printf("MALLOC RETURNED NULL %zu\n", size);
		}
		memcpy(new, ptr, node_size < size ? node_size : size);
		free(ptr);
		return new;
	}
	// It really should never go here, but its left as a precaution
	printf("LIBC REALLOC\n");
	return NULL;
}

void *calloc(size_t count, size_t size){
	//printf("Calloc was called\n");
	if (count == 0 || size == 0) return NULL;
	size_t fsize = count * size;
	void *result = malloc(fsize);
	assert(result != NULL);
	//memset(result, 0, fsize); //allocated file should be zerod...
	return result;
}

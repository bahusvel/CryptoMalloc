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

static pthread_mutex_t mymutex = PTHREAD_MUTEX_INITIALIZER;

/* These are no longer used, CryptoMalloc does not use normal malloc
static void *(*libc_malloc)(size_t);
static void *(*libc_realloc)(void *, size_t);
static void *(*libc_calloc)(size_t, size_t);
static void (*libc_free)(void *);
*/

typedef struct cor_map_node {
    void			*key;
	unsigned long	allocid;
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

static void cor_map_set(cor_map* map, cor_map_node *node){ // can be inlined
	node->next = map->first;
	map->first = node;
}


static char *CRYPTO_PATH = "/Volumes/CryptoDisk/";
static int PAGE_SIZE;
static volatile unsigned long __crypto_allocid = 0;
static cor_map mem_map = {NULL};
static const char fend = 0;

__attribute__((constructor))
static void crypto_malloc_ctor(){
	PAGE_SIZE = getpagesize();
	char *envPath = getenv("CRYPTO_PATH");
	if (envPath != NULL) {
		CRYPTO_PATH = envPath;
	}
	/* These are no longer used, CryptoMalloc does not use normal malloc
	*(void **)&libc_malloc = dlsym(RTLD_NEXT, "malloc");
	*(void **)&libc_realloc = dlsym(RTLD_NEXT, "realloc");
	*(void **)&libc_calloc = dlsym(RTLD_NEXT, "calloc");
	*(void **)&libc_free = dlsym(RTLD_NEXT, "free");
	*/
}


__attribute__((destructor))
static void crypto_malloc_dtor(){
	// not for leak management, just for wiping files;
}


void* malloc(size_t size){
	if (size == 0) return NULL;
	size = size + sizeof(cor_map_node);
	pthread_mutex_lock(&mymutex);
    char path[200];
    sprintf(path, "%s%016lx.mem", CRYPTO_PATH, __crypto_allocid++);
	int fnum = open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
	if (fnum < 0) {
		perror("Open");
	}
    lseek(fnum, size - 1, SEEK_SET);
    write(fnum, &fend, 1);
    fsync(fnum);
    void *crypto_mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fnum, 0);
	close(fnum);
    if (crypto_mem != MAP_FAILED) {
		((cor_map_node*)crypto_mem)->key = crypto_mem + sizeof(cor_map_node);
		((cor_map_node*)crypto_mem)->allocid = __crypto_allocid - 1;
		((cor_map_node*)crypto_mem)->alloc_size = size;
        cor_map_set(&mem_map, (cor_map_node*)crypto_mem);
		pthread_mutex_unlock(&mymutex);
        return crypto_mem + sizeof(cor_map_node);
    } else {
		perror("mmap");
		printf("File Descriptor is: %d, %lu\n", fnum, __crypto_allocid-1);
        //close(fnum);
		pthread_mutex_unlock(&mymutex);
		errno = ENOMEM;
        return NULL;
    }
}

void free(void *ptr){
	/*
	Some code relies on how free works, free doesnt discard memory straight away
	it keeps the most recent free bit of memory and it can still be referenced
	this is done for the purposes of realloc implementation in Linux
	
	*** THIS ONE DOESNT DO THAT ***
	Hence some software that relies on it (which it shouldn't, will crash)
	*/
	if (ptr == NULL) return;
	pthread_mutex_lock(&mymutex);
    cor_map_node *node;
	if ((node = cor_map_delete(&mem_map, ptr)) != NULL){
		//printf("FOUND NODE %lu\n", node.alloc_size);
		//munmap(node, node->alloc_size); //UNCOMMENT AFTER DONE TESTING
		//char path[200];
		//sprintf(path, "%s%016lx.mem", CRYPTO_PATH, node.allocid);
		//unlink(path);
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
	cor_map_node *node;
	void *new = NULL;
	if ((node = cor_map_get(&mem_map, ptr)) != NULL){
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
	memset(result, 0, fsize);
	return result;
}
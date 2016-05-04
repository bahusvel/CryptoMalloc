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

static pthread_mutex_t mymutex=PTHREAD_MUTEX_INITIALIZER;

static void *(*libc_malloc)(size_t);
static void *(*libc_realloc)(void *, size_t);
static void *(*libc_calloc)(size_t, size_t);
static void (*libc_free)(void *);

typedef struct MemNode{
    int				fd;
	unsigned long	allocid;
    size_t			alloc_size;
} MemNode;

typedef struct cor_map_node {
    void			*key;
	MemNode			node;
    struct cor_map_node *next;
} cor_map_node;

typedef struct cor_map{
    cor_map_node *first;
    cor_map_node *last;
} cor_map;

static int cor_map_get(cor_map* map, void *key, MemNode *node){
    cor_map_node *np = map->first;
    while (np != NULL) {
        if (np->key == key) {
			*node = np->node;
            return 1;
        }
        np = np->next;
    }
    return 0;
}

static cor_map_node *create_node(void *key, MemNode *node){
	if (libc_malloc == NULL){
		printf("libc malloc was not retrieved");
	}
    cor_map_node *mnode = libc_malloc(sizeof(cor_map_node));
    mnode->key = key;
	mnode->node = *node;
    mnode->next = NULL;
    return mnode;
}

static void cor_map_set(cor_map* map, void *key, MemNode *node){
	if (map->first == NULL) {
		map->first = create_node(key, node);
		map->last = map->first;
	} else {
		cor_map_node *last_node = map->last;
		last_node->next = create_node(key, node);
		map->last = last_node->next;
	}
}


static char *CRYPTO_PATH = "/Volumes/CryptoDisk/";
static int PAGE_SIZE;
static volatile unsigned long __crypto_allocid = 0;
static cor_map mem_map;
static const char fend = 0;

__attribute__((constructor))
static void crypto_malloc_ctor(){
	PAGE_SIZE = getpagesize();
	char *envPath = getenv("CRYPTO_PATH");
	if (envPath != NULL) {
		CRYPTO_PATH = envPath;
	}
	*(void **)&libc_malloc = dlsym(RTLD_NEXT, "malloc");
	*(void **)&libc_realloc = dlsym(RTLD_NEXT, "realloc");
	*(void **)&libc_calloc = dlsym(RTLD_NEXT, "calloc");
	*(void **)&libc_free = dlsym(RTLD_NEXT, "free");
}


__attribute__((destructor))
static void crypto_malloc_dtor(){
	cor_map_node *current = mem_map.first;
	while (current != NULL) {
		//free(current->key);
		current = current->next;
	}
}

void* malloc(size_t size){
	/*
	if (!libc_malloc){
		libc_malloc = dlsym(RTLD_NEXT, "malloc");
		libc_calloc = dlsym(RTLD_NEXT, "realloc");
		libc_realloc = dlsym(RTLD_NEXT, "calloc");
		libc_free = dlsym(RTLD_NEXT, "free");
	}
	 */
	if (size == 0) return NULL;
	size = ((size / 4096L) + 1L) * 4096;
	pthread_mutex_lock(&mymutex);
    char path[200];
    sprintf(path, "%s%016lx.mem", CRYPTO_PATH, __crypto_allocid++);
	int fnum = open(path, O_RDWR | O_CREAT | O_SYNC | O_TRUNC, S_IRWXU); // O_DIRECT for linux?
    lseek(fnum, size - 1, SEEK_SET);
    write(fnum, &fend, 1);
    fsync(fnum);
    void *crypto_mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fnum, 0);
    if (crypto_mem != MAP_FAILED) {
		MemNode node = {fnum, __crypto_allocid - 1, size};
        cor_map_set(&mem_map, crypto_mem, &node);
		pthread_mutex_unlock(&mymutex);
		//printf("Malloc Succeded %lu\n", node.allocid);
        return crypto_mem;
    } else {
		//printf("Malloc Failed\n");
        close(fnum);
		pthread_mutex_unlock(&mymutex);
		errno = ENOMEM;
        return NULL;
    }
}

void free(void *ptr){
	if (ptr == NULL) return;
    //assert(mem_map != NULL);
	pthread_mutex_lock(&mymutex);
    MemNode node;
	if (cor_map_get(&mem_map, ptr, &node) == 1){
		//printf("FOUND NODE %lu\n", node.alloc_size);
		//munmap(ptr, node.alloc_size); UNCOMMENT AFTER DONE TESTING
		//close(node.fd);
		char path[200];
		sprintf(path, "%s%016lx.mem", CRYPTO_PATH, node.allocid);
		//unlink(path);
	} else {
		printf("LIBC FREE\n");
		libc_free(ptr);
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
	MemNode node;
	void *new = NULL;
	if (cor_map_get(&mem_map, ptr, &node)){
		new = malloc(size);
		memcpy(new, ptr, node.alloc_size < size ? node.alloc_size : size);
		free(ptr);
		return new;
	}
	printf("LIBC REALLOC\n");
	return libc_realloc(ptr, size);
}

void *calloc(size_t count, size_t size){
	printf("Calloc was called\n");
	if (count == 0 || size == 0) return NULL;
	size_t fsize = count * size;
	void *result = malloc(fsize);
	if (result == NULL) {
		printf("OOPS\n");
	}
	memset(result, 0, fsize);
	return result;
}
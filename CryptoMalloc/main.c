//
//  main.c
//  CryptoMalloc
//
//  Created by denis lavrov on 3/05/16.
//  Copyright © 2016 Denis Lavrov. All rights reserved.
//

#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

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
    cor_map_node *mnode = libc_malloc(sizeof(cor_map_node));
    mnode->key = key;
	mnode->node = *node;
    mnode->next = NULL;
    return mnode;
}

static void cor_map_set(cor_map* map, void *key, MemNode *node){
    MemNode tnode;
    if (cor_map_get(map, key, &tnode) == 0) {
        if (map->first == NULL) {
            map->first = create_node(key, node);
            map->last = map->first;
        } else {
            cor_map_node *last_node = map->last;
            last_node->next = create_node(key, node);
            map->last = last_node->next;
        }
    }
}


static const char CRYPTO_PATH[] = "/Volumes/CryptoDisk/";
static volatile unsigned long __crypto_allocid = 0;
static cor_map mem_map;
static const char fend = 0;

__attribute__((constructor))
static void crypto_malloc_ctor(){
	if (!libc_malloc){
		libc_malloc = dlsym(RTLD_NEXT, "malloc");
		libc_calloc = dlsym(RTLD_NEXT, "realloc");
		libc_realloc = dlsym(RTLD_NEXT, "calloc");
		libc_free = dlsym(RTLD_NEXT, "free");
		printf("It worked?");
	}
}

__attribute__((destructor))
static void crypto_malloc_dtor(){
	cor_map_node *current = mem_map.first;
	while (current != NULL) {
		MemNode node = current->node;
		munmap(current->key, node.alloc_size);
		close(node.fd);
		char path[sizeof(CRYPTO_PATH) + 20];
		sprintf(path, "%s%016lx.mem", CRYPTO_PATH, node.allocid);
		unlink(path);
		current = current->next;
	}
}

void* malloc(size_t size){
	if (!libc_malloc){
		libc_malloc = dlsym(RTLD_NEXT, "malloc");
		libc_calloc = dlsym(RTLD_NEXT, "realloc");
		libc_realloc = dlsym(RTLD_NEXT, "calloc");
		libc_free = dlsym(RTLD_NEXT, "free");
	}
							 
    char path[sizeof(CRYPTO_PATH) + 20];
    sprintf(path, "%s%016lx.mem", CRYPTO_PATH, __crypto_allocid++);
    int fnum = open(path, O_RDWR | O_CREAT, S_IRWXU);
    lseek(fnum, size - 1, SEEK_SET);
    write(fnum, &fend, 1);
    fsync(fnum);
    void *crypto_mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fnum, 0);
    if (crypto_mem != MAP_FAILED) {
		MemNode node = {fnum, __crypto_allocid - 1, size};
        cor_map_set(&mem_map, crypto_mem, &node);
        return crypto_mem;
    } else {
        close(fnum);
        return NULL;
    }
}

void free(void *ptr){
    //assert(mem_map != NULL);
    MemNode node;
	if (cor_map_get(&mem_map, ptr, &node)){
		munmap(ptr, node.alloc_size);
		close(node.fd);
		char path[sizeof(CRYPTO_PATH) + 20];
		sprintf(path, "%s%016lx.mem", CRYPTO_PATH, node.allocid);
		unlink(path);
	} else {
		libc_free(ptr);
	}
}

// TODO: Use a more sophisticated realloc, for better performance
void *realloc(void *ptr, size_t size){
	free(ptr);
	return malloc(size);
}
void *calloc(size_t count, size_t size){
	return malloc(count * size);
}

/*
int main(int argc, const char * argv[]) {
    // insert code here...
    char *crypto_string = crypto_malloc(100);
    strcpy(crypto_string, "ThisIsMyPassword");
    printf("%s\n", crypto_string);
    crypto_free(crypto_string);
    return 0;
}
*/
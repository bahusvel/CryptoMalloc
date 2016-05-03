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
    int     fd;
    size_t  alloc_size;
} MemNode;

typedef struct cor_map_node {
    void *key;
    int  fd;
    size_t alloc_size;
    struct cor_map_node *next;
} cor_map_node;

typedef struct cor_map{
    cor_map_node *first;
    cor_map_node *last;
} cor_map;

int cor_map_get(cor_map* map, void *key, MemNode *node){
    cor_map_node *np = map->first;
    while (np != NULL) {
        if (np->key == key) {
            node->fd = np->fd;
            node->alloc_size = np->alloc_size;
            return 1;
        }
        np = np->next;
    }
    return 0;
}

cor_map_node *create_node(void *key, int fd, size_t alloc_size){
    cor_map_node *node = libc_malloc(sizeof(cor_map_node));
    node->key = key;
    node->fd = fd;
    node->alloc_size = alloc_size;
    node->next = NULL;
    return node;
}

void cor_map_set(cor_map* map, void *key, int fd, size_t size){
    MemNode node;
    if (cor_map_get(map, key, &node) == 0) {
        if (map->first == NULL) {
            map->first = create_node(key, fd, size);
            map->last = map->first;
        } else {
            cor_map_node *last_node = map->last;
            last_node->next = create_node(key, fd, size);
            map->last = last_node->next;
        }
    }
}


static const char CRYPTO_PATH[] = "/Volumes/CryptoDisk/";
static volatile unsigned long __crypto_allocid = 0;
static cor_map mem_map;
static const char *fend = "0";

void* malloc(size_t size){
    if (!libc_malloc){
        libc_malloc = dlsym(RTLD_NEXT, "malloc");
        libc_calloc = dlsym(RTLD_NEXT, "realloc");
        libc_realloc = dlsym(RTLD_NEXT, "calloc");
        libc_free = dlsym(RTLD_NEXT, "free");
    }
    char path[sizeof(CRYPTO_PATH) + 20];
    sprintf(path, "%s%016lx.mem", CRYPTO_PATH, __crypto_allocid++);
    int fnum = open(path, O_RDWR | O_CREAT, 0);
    lseek(fnum, size - 1, SEEK_SET);
    write(fnum, fend, 1);
    fsync(fnum);
    void *crypto_mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fnum, 0);
    if (crypto_mem != MAP_FAILED) {
        cor_map_set(&mem_map, crypto_mem, fnum, size);
        return crypto_mem;
    } else {
        close(fnum);
        return NULL;
    }
}

void free(void *ptr){
    //assert(mem_map != NULL);
    MemNode node;
    cor_map_get(&mem_map, ptr, &node);
    munmap(ptr, node.alloc_size);
    close(node.fd);
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
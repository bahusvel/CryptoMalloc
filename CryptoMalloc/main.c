//
//  main.c
//  CryptoMalloc
//
//  Created by denis lavrov on 3/05/16.
//  Copyright © 2016 Denis Lavrov. All rights reserved.
//

#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include "cor_map.h"

const char CRYPTO_PATH[] = "/Volumes/CryptoDisk/";
volatile unsigned long __crypto_allocid = 0;
cor_map *mem_map;

void* crypto_malloc(size_t size){
    if (mem_map == NULL){
        mem_map = cor_map_create();
    }
    char path[sizeof(CRYPTO_PATH) + 20];
    sprintf(path, "%s%016lx.mem", CRYPTO_PATH, __crypto_allocid++);
    //strcpy(path, CRYPTO_PATH);
    //strcat(path, "file.mem");
    FILE *fp = fopen(path, "w+");
    fseek(fp, size - 1, SEEK_SET);
    fputc('\0', fp);
    fflush(fp);
    int fnum = fileno(fp);
    void *crypto_mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fnum, 0);
    if (crypto_mem != MAP_FAILED) {
        cor_map_set(mem_map, crypto_mem, fp, size);
        return crypto_mem;
    } else {
        printf("broke\n");
        fclose(fp);
        return NULL;
    }
}

void crypto_free(void *ptr){
    //assert(mem_map != NULL);
    MemNode node;
    cor_map_get(mem_map, ptr, &node);
    munmap(ptr, node.alloc_size);
    fclose(node.fp);
}

int main(int argc, const char * argv[]) {
    // insert code here...
    char *crypto_string = crypto_malloc(100);
    strcpy(crypto_string, "ThisIsMyPassword");
    printf("%s\n", crypto_string);
    crypto_free(crypto_string);
    return 0;
}

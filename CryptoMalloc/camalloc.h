#ifndef _CAMALLOC_
#define _CAMALLOC_
#include <stdlib.h>

#ifdef __APPLE__
static void *(*__libc_malloc)(size_t size);
static void *(*__libc_free)(void *ptr);
static void *(*__libc_realloc)(void *ptr, size_t size);
static void *(*__libc_calloc)(size_t count, size_t size);
#else
extern void *__libc_malloc(size_t size);
extern void __libc_free(void *ptr);
extern void *__libc_realloc(void *ptr, size_t size);
extern void *__libc_calloc(size_t count, size_t size);
#endif

#define crypto_malloc malloc
#define crypto_free free
#define crypto_realloc realloc
#define crypto_calloc calloc

int camalloc_decrypt(void *address);
int camalloc_encrypt(void *address);

// libc

#define libc_malloc __libc_malloc
#define libc_free __libc_free
#define libc_realloc __libc_realloc
#define libc_calloc __libc_calloc

#endif //_CAMALLOC_

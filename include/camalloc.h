#ifndef _CAMALLOC_
#define _CAMALLOC_
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

inline void safe_print(const char *message) {
	write(1, message, strlen(message));
}

void ca_nocipher(void *address);
void ca_recipher(void *address);
void ca_encrypt(void *address);
void ca_decrypt(void *address);

// libc

#define libc_malloc __libc_malloc
#define libc_free __libc_free
#define libc_realloc __libc_realloc
#define libc_calloc __libc_calloc

#endif //_CAMALLOC_

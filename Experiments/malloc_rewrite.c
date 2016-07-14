#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#if __x86_64__
#define HIJACK_SIZE 16
#define HIJACK_CODE                                                            \
	"\x50\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x87\x04\x24\xC3"
#else
#define HIJACK_SIZE 6
#define HIJACK_CODE "\x68\x00\x00\x00\x00\xc3"
#endif

typedef struct sym_hook {
	void *addr;
	unsigned char o_code[HIJACK_SIZE];
	unsigned char n_code[HIJACK_SIZE];
} sym_hook;

sym_hook malloc_hook;

void disable_wp(void *target) {
	// FIXME 8192 is to handle the edge case when HIJACK_SIZE crosses a page
	// boundary, there is a smarter way to do this, but I'm lazy
	mprotect((unsigned long)target & ~0xFFF, 8192,
			 PROT_WRITE | PROT_READ | PROT_EXEC);
}
void enable_wp(void *target) {
	mprotect((unsigned long)target & ~0xFFF, 8192, PROT_EXEC | PROT_READ);
}

void hijack_resume(sym_hook *hook) {
	disable_wp(hook->addr);
	memcpy(hook->addr, hook->n_code, HIJACK_SIZE);
	enable_wp(hook->addr);
}

void hijack_stop(sym_hook *hook) {
	disable_wp(hook->addr);
	memcpy(hook->addr, hook->o_code, HIJACK_SIZE);
	enable_wp(hook->addr);
}

sym_hook hijack_start(void *target, void *new) {
	sym_hook hook;
	hook.addr = target;

	// NOTE push $addr; ret
	memcpy(hook.n_code, HIJACK_CODE, HIJACK_SIZE);

#ifdef __x86_64__
	*(unsigned long *)(&hook.n_code[3]) = (unsigned long)new;
#else
	*(unsigned int *)(&hook.n_code[1]) = (unsigned int)new;
#endif

	memcpy(hook.o_code, target, HIJACK_SIZE);
	disable_wp(target);
	memcpy(target, hook.n_code, HIJACK_SIZE);
	enable_wp(target);

	return hook;
}

void *fake_malloc(size_t size) {
	printf("In the fake malloc\n");
	hijack_stop(&malloc_hook); // this can be replaced by a trampoline instead
	void *ret = malloc(size);
	hijack_resume(&malloc_hook);
	return ret;
}

int main() {
	printf("Location of malloc is %p\n", malloc);
	printf("Location of fake malloc is %p\n", fake_malloc);
	malloc_hook = hijack_start(malloc, fake_malloc);
	printf("Malloc said %p\n", malloc(0));
}

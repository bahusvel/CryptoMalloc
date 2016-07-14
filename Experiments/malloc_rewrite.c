#include "distorm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define MAX_HIJACK_SIZE 16
#ifdef __x86_64__
#define DECODE_BITS Decode64Bits
#else
#define DECODE_BITS Decode32Bits
#endif

#define DECODE_MAX_INSTRUCTIONS 16

typedef struct sym_hook {
	void *addr;
	int hijack_size;
	unsigned char o_code[MAX_HIJACK_SIZE];
	unsigned char n_code[MAX_HIJACK_SIZE];
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
	memcpy(hook->addr, hook->n_code, hook->hijack_size);
	enable_wp(hook->addr);
}

void hijack_stop(sym_hook *hook) {
	disable_wp(hook->addr);
	memcpy(hook->addr, hook->o_code, hook->hijack_size);
	enable_wp(hook->addr);
}

static int hook_whole_size(void *target, int hook_code_size) {
	_DecodedInst decodedInstructions[DECODE_MAX_INSTRUCTIONS];
	unsigned int decodedCount = 0;
	_DecodeResult result =
		distorm_decode(0, target, 32, DECODE_BITS, decodedInstructions,
					   DECODE_MAX_INSTRUCTIONS, &decodedCount);

	if (result == DECRES_INPUTERR) {
		printf("Input error\n");
		exit(-1);
	}
	int whole_size = 0, i = 0;
	while (whole_size < hook_code_size) {
		if (i > decodedCount) {
			printf("Didn't decode enough !!!\n");
			exit(-1);
		}
		whole_size += decodedInstructions[i++].size;
	}
	return whole_size;
}

sym_hook hijack_start(void *target, void *new) {
	sym_hook hook;
	hook.addr = target;
	// check if jump needs to be a long jump
	if (labs(new - target) > 4 * 1024 * 1024) {
		hook.hijack_size = 16;
		/* NOTE
		push rax;
		movabs rax, $addr;
		xchg rax, [rsp];
		ret;
		*/
		memcpy(
			hook.n_code,
			"\x50\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x87\x04\x24\xC3",
			16);
		*(unsigned long *)(&hook.n_code[3]) = (unsigned long)new;
	} else {
		hook.hijack_size = 6;
		// NOTE push $addr; ret
		memcpy(hook.n_code, "\x68\x00\x00\x00\x00\xc3", 6);
		*(unsigned int *)(&hook.n_code[1]) = (unsigned int)new;
	}
	memcpy(hook.o_code, target, hook.hijack_size);
	disable_wp(target);
	memcpy(target, hook.n_code, hook.hijack_size);
	enable_wp(target);
	printf("Changed the code\n\n");
	return hook;
}

/*
void hijack_trampoline(sym_hook *hook, void *trampoline) {
	disable_wp(trampoline);
	memcpy(trampoline, hook->o_code, hook->hijack_size);
	memcpy(void *, const void *, size_t);
	enable_wp(trampoline);
}
*/

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

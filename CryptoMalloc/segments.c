#include <mach-o/getsect.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

char *password = "Denis Lavrov Is Awesome";
unsigned long next_addr = 0;
static struct sigaction old_handler;
static void null_handler(int signum, siginfo_t *info, void *context) {
	write(1, "printing", 5);
	if (next_addr < get_etext() + 100) {
		next_addr++;
	}
}

int main(int argc, char *argv[]) {
	// setting up signal handler
	static struct sigaction sa;
	sa.sa_sigaction = null_handler;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGSEGV);
	sa.sa_flags = SA_SIGINFO | SA_RESTART;

	if (sigaction(SIGSEGV, &sa, &old_handler) < 0) {
		perror("Signal Handler Installation Failed:");
		abort();
	}

	printf("    program text (etext)      %10p\n", (void *)get_etext());
	printf("    initialized data (edata)  %10p\n", (void *)get_edata());
	printf("    uninitialized data (end)  %10p\n", (void *)get_end());
	long edata_length = get_edata() - get_etext();
	printf("	initialized data size: %ld\n", edata_length);
	write(0, get_etext(), 572);
	exit(EXIT_SUCCESS);
}

#include <errno.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
	pid_t child;
	long orig_eax;
	child = fork();
	if (child == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execl("/bin/ls", "ls", NULL);
	} else {
		int status;
		int insyscall;
		while (1) {
			wait(&status);
			if (WIFEXITED(status))
				break;

			struct user_regs_struct regs;
			ptrace(PTRACE_GETREGS, child, NULL, &regs);
			if (insyscall == 0) {
				insyscall = 1;
			} else {
				printf("syscall %llu returned %llu\n", regs.orig_rax, regs.rax);
				if ((long long)regs.rax == EFAULT) {
					printf("SYSCALL %llu\n SEGFAULTED", regs.orig_rax);
				}
				insyscall = 0;
			}
			ptrace(PTRACE_SYSCALL, child, NULL, NULL);
		}
	}
	return 0;
}

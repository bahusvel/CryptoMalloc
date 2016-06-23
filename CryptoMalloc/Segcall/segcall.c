#include <asm/siginfo.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/sched.h>

/*
How it should work...
1) Process that wishes to receive segfaults must register to do so with this
kernel module
2) This module hijacks copy_from_user(), to its own version, that runs the real
copy_from_user() and if that returns non-zero, it checks whether the call
originated from the process that registered (current->pid) current global
variable can be used to check current context process
3) If it is then this module will send a SIGSEGV to the process with the
corresponding address
*/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Denis Lavrov");
MODULE_DESCRIPTION("Trigger segfault to the calling task if invalid address is "
				   "given to a syscall.");
MODULE_VERSION("0.1");

int pid_to_kill = 0;
module_param(pid_to_kill, int, 0);

/*
static int set_page_rw(long unsigned int _addr) {
	struct page *pg;
	pgprot_t prot;
	pg = virt_to_page(_addr);
	prot.pgprot = VM_READ | VM_WRITE;
	return change_page_attr(pg, 1, prot);
}

static int set_page_ro(long unsigned int _addr) {
	struct page *pg;
	pgprot_t prot;
	pg = virt_to_page(_addr);
	prot.pgprot = VM_READ;
	return change_page_attr(pg, 1, prot);
}
*/

static void send_signal(int sig, int pid) {
	struct siginfo info;
	memset(&info, 0, sizeof(struct siginfo));
	info.si_signo = sig;
	info.si_code = SI_KERNEL;
	info.si_int = 1234;
	rcu_read_lock();
	struct task_struct *current_task = pid_task(find_vpid(pid), PIDTYPE_PID);
	rcu_read_unlock();
	int ret = send_sig_info(sig, &info, current_task);
	if (ret < 0) {
		printk("error sending signal\n");
	}
}

static int __init segcall_init(void) {
	printk(KERN_INFO "Segcall loaded! Gonna kill: %d\n", pid_to_kill);
	if (pid_to_kill != 0) {
		send_signal(SIGTERM, pid_to_kill);
	}
	return 0;
}

void __exit segcall_exit(void) { printk(KERN_INFO "Segcall unloaded!\n"); }

module_init(segcall_init);
module_exit(segcall_exit);

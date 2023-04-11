
#define pr_fmt(fmt) "syscall_hooking: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <asm/signal.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/fs_struct.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>

MODULE_DESCRIPTION("System call hooking to protect a process from exploit attempts");
MODULE_AUTHOR("Stefan Pana <stefanpana00@gmail.com>");
MODULE_LICENSE("GPL");

#define NETLINK_TEST 17
static struct sock *socketptr = NULL;
int PID = -1;

static void nl_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh = NULL;
    if (skb == NULL) {
        printk("skb is NULL\n");
        return ;
    }

    nlh = (struct nlmsghdr *)skb->data;
	PID = nlh->nlmsg_pid;

    printk(KERN_INFO "%s: received netlink message payload: %s\nPID: %d\n", __FUNCTION__, NLMSG_DATA(nlh), PID);


	// SEND MESSAGE TO USER SPACE
	char *msg = "Hello msg from kernel";
	int msg_size = strlen(msg);
	struct sk_buff *skb_out = nlmsg_new(msg_size, 0);    //nlmsg_new - Allocate a new netlink message: skb_out

    if (!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);   // Add a new netlink message to an skb
    NETLINK_CB(skb_out).dst_group = 0;                  
    strncpy(nlmsg_data(nlh), msg, msg_size); //char *strncpy(char *dest, const char *src, size_t count)
    int res = nlmsg_unicast(socketptr, skb_out, PID); 

    if (res < 0) {
        printk(KERN_INFO "Error while sending back to user\n");
	}
}

struct netlink_kernel_cfg cfg = {
    .input = nl_recv_msg,
};

unsigned int target_fd = 0;
unsigned int target_pid = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name) {
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name) {
	return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs) {
	return fregs;
}
#endif

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook) {
	hook->address = lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs) {
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook) {
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook) {
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count) {
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count) {
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

static char *duplicate_filename(const char __user *filename) {
	char *kernel_filename;

	kernel_filename = kmalloc(4096, GFP_KERNEL);
	if (!kernel_filename)
		return NULL;

	if (strncpy_from_user(kernel_filename, filename, 4096) < 0) {
		kfree(kernel_filename);
		return NULL;
	}

	return kernel_filename;
}

static char *alloc_string(const int size) {
	char *string;

	string = kmalloc(size, GFP_KERNEL);
	if (!string)
		return NULL;

	return string;
}

// WRITE 32 BIT
static asmlinkage long (*real_sys_write_32)(struct pt_regs *regs);

static asmlinkage long fh_sys_write_32(struct pt_regs *regs) {
	int ret_status;
	long ret;
	int signum;
	struct task_struct *task;
	struct kernel_siginfo info;

	task = current;
	signum = SIGKILL;

	if (task->pid == target_pid) {
		pr_info("write32 by process %d\nregs->di: %lu\ntarget_fd: %d\n", task->pid, regs->bx, target_fd);
		if (regs->bx == target_fd) {
			pr_info("write32 done by process %d to target file.\n", task->pid);

			memset(&info, 0, sizeof(struct kernel_siginfo));
			info.si_signo = signum;

			ret_status = send_sig_info(signum, &info, task);

			if (ret_status < 0) {
				printk(KERN_INFO "error sending signal\n");
			} else {
				printk(KERN_INFO "Target has been killed\n");
				return 0;
			}
		}
	}

	ret = real_sys_write_32(regs);

	return ret;
}

// WRITE 64 BIT
static asmlinkage long (*real_sys_write_64)(struct pt_regs *regs);

static asmlinkage long fh_sys_write_64(struct pt_regs *regs) {
	int ret_status;
	long ret;
	int signum;
	struct task_struct *task;
	struct kernel_siginfo info;

	task = current;
	signum = SIGKILL;

	if (task->pid == target_pid) {
		pr_info("write64 by process %d\nregs->di: %lu\ntarget_fd: %d\n", task->pid, regs->di, target_fd);
		if (regs->di == target_fd) {
			pr_info("write64 done by process %d to target file.\n", task->pid);

			memset(&info, 0, sizeof(struct kernel_siginfo));
			info.si_signo = signum;

			ret_status = send_sig_info(signum, &info, task);

			if (ret_status < 0) {
				printk(KERN_INFO "error sending signal\n");
			} else {
				printk(KERN_INFO "Target has been killed\n");
				return 0;
			}
		}
	}

	ret = real_sys_write_64(regs);

	return ret;
}

// OPENAT 32 BIT
static asmlinkage long (*real_sys_openat_32)(struct pt_regs *regs);

static asmlinkage long fh_sys_openat_32(struct pt_regs *regs) {
	long ret;
	char *kernel_filename;
	struct task_struct *task;
	task = current;

	kernel_filename = duplicate_filename((void*) regs->cx);

	// get_absolute_path(kernel_filename);
	// pr_info("openat32: %s\n", kernel_filename);

	// pr_info("%s\n", kernel_filename);
	if (strncmp(kernel_filename, "/home/feather/student/licenta/syscall_hooking/test_open+write/file.txt", 70) == 0) {
		pr_info("our file is opened32 by process with id: %d\n", task->pid);
		pr_info("opened32 file : %s\n", kernel_filename);
		kfree(kernel_filename);
		ret = real_sys_openat_32(regs);
		pr_info("fd returned is %ld\n", ret);
		target_fd = ret;
		target_pid = task->pid;
		return ret;
	}

	kfree(kernel_filename);
	ret = real_sys_openat_32(regs);

	return ret;
}

// OPENAT 64 BIT
static asmlinkage long (*real_sys_openat_64)(struct pt_regs *regs);

static asmlinkage long fh_sys_openat_64(struct pt_regs *regs) {
	long ret;
	char *kernel_filename;
	struct task_struct *task;
	task = current;

	kernel_filename = duplicate_filename((void*) regs->si);

	// get_absolute_path(kernel_filename);
	// pr_info("openat32: %s\n", kernel_filename);

	// pr_info("%s\n", kernel_filename);
	if (strncmp(kernel_filename, "/home/feather/student/licenta/syscall_hooking/test_open+write/file.txt", 70) == 0) {
		pr_info("our file is opened64 by process with id: %d\n", task->pid);
		pr_info("opened64 file : %s\n", kernel_filename);
		kfree(kernel_filename);
		ret = real_sys_openat_64(regs);
		pr_info("fd returned is %ld\n", ret);
		target_fd = ret;
		target_pid = task->pid;
		return ret;
	}

	kfree(kernel_filename);
	ret = real_sys_openat_64(regs);

	return ret;
}

// EXECVE 32 BIT
static asmlinkage long (*real_sys_execve_32)(struct pt_regs *regs);

static asmlinkage long fh_sys_execve_32(struct pt_regs *regs) {
	long ret;
	struct task_struct *task;
	struct path pwd;
	char *pwd_path_raw;
	char *syscall_path_argument = duplicate_filename((void *)regs->bx);
	char *x = alloc_string(1000);

	task = current;

	if (strncmp(syscall_path_argument, "/bin/sh", 7) == 0) {
		// get current working directory
		get_fs_pwd(task->fs, &pwd);		
		pwd_path_raw = dentry_path_raw(pwd.dentry, x, 999);

		pr_info("execve32 with path %s\n", pwd_path_raw);
	}

	ret = real_sys_execve_32(regs);

	kfree(syscall_path_argument);
	kfree(x);
	return ret;
}

// EXECVE 64 BIT
static asmlinkage long (*real_sys_execve_64)(struct pt_regs *regs);

static asmlinkage long fh_sys_execve_64(struct pt_regs *regs) {
	long ret;
	struct task_struct *task;
	struct path pwd;
	char *pwd_path_raw;
	char *syscall_path_argument = duplicate_filename((void *)regs->di);
	char *x = alloc_string(1000);
	// char possible_full_name[500];

	task = current;

	// get current working directory
	get_fs_pwd(task->fs, &pwd);
	pwd_path_raw = dentry_path_raw(pwd.dentry, x, 999);

	// strcat(possible_full_name, pwd_path_raw);
	// strcat(possible_full_name, "/");
	// strcat(possible_full_name, syscall_path_argument);

	if ((strncmp(syscall_path_argument, "/bin/sh", 7) == 0) ||
		 strncmp(syscall_path_argument, "/usr/bin/sh", 11) == 0) {
		pr_info("execve64 with argument %s\npwd_path: %s\n", syscall_path_argument, pwd_path_raw);
	}

	ret = real_sys_execve_64(regs);

	kfree(syscall_path_argument);
	kfree(x);
	return ret;
}


/*
 * 32 bit syscalls naming convention
 */
#define SYSCALL_NAME_32(name) ("__ia32_" name)

#define HOOK_32(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME_32(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}


/*
 * 64 bit syscalls naming convention
 */
#define SYSCALL_NAME_64(name) ("__x64_" name)

#define HOOK_64(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME_64(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook syscall_hooks[] = {
	// 32 bit
	HOOK_32("sys_write", fh_sys_write_32, &real_sys_write_32),    // write
	HOOK_32("compat_sys_openat", fh_sys_openat_32, &real_sys_openat_32), // open
	HOOK_32("compat_sys_execve", fh_sys_execve_32, &real_sys_execve_32), // execv

	// 64 bit
	HOOK_64("sys_write", fh_sys_write_64, &real_sys_write_64), // write
	HOOK_64("sys_openat", fh_sys_openat_64, &real_sys_openat_64), // openat
	HOOK_64("sys_execve", fh_sys_execve_64, &real_sys_execve_64), // execv
};

static int fh_init(void) {
	int err;

	err = fh_install_hooks(syscall_hooks, ARRAY_SIZE(syscall_hooks));
	if (err) {
		pr_info("module not loaded, error!\n");
		return err;
	}

	pr_info("Initializing Netlink Socket\n");
    socketptr = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
	if (!socketptr) {
		pr_info("Error creating socket.\n");
		return 0;
	}

	pr_info("module loaded\n");

	return 0;
}
module_init(fh_init);

static void fh_exit(void) {
	fh_remove_hooks(syscall_hooks, ARRAY_SIZE(syscall_hooks));
	sock_release(socketptr->sk_socket);

	pr_info("module unloaded\n");
}
module_exit(fh_exit);

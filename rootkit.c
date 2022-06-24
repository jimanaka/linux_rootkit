#include <linux/module.h>
#include <linux/kernel.h>
#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jake Imanaka");
MODULE_DESCRIPTION("My first rootkit");
MODULE_VERSION("0.00");

static int __init rootkit_init(void){
   printk(KERN_INFO "rootkit: Loaded >:-\n");

   return 0;
}

static void __exit rootkit_exit(void){
   printk(KERN_INFO "rootkit: Unloaded :-(\n");

}

module_init(rootkit_init);
module_exit(rootkit_exit);


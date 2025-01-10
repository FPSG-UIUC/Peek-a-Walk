#include <linux/init.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>

// Module metadata
MODULE_AUTHOR("Alan Wang");
MODULE_DESCRIPTION("PWSC Kernel Memory Scanner");
MODULE_LICENSE("GPL");

static size_t u64_from_user(u64 *value, const char *buf, size_t *len, loff_t *off)
{
	if (copy_from_user(value, buf, 8))
		return -1;

	*off += 8;
	return 0;
}

static size_t u64_to_user(char __user *buf, size_t len, loff_t *off, u64 value)
{
	if (*off > 0)
		return 0;

	if (copy_to_user(buf, &value, 8))
		return -EFAULT;

	*off += 8;
	return 8;
}

static uint64_t cur_secret_byte = 0; 

static ssize_t tool_read_op(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
    return u64_to_user(buf, len, off, cur_secret_byte);
}

static ssize_t tool_write_op(struct file *filp, const char *buf, size_t len, loff_t *off)
{
    u64 addr;
	if (u64_from_user(&addr, buf, &len, off)) {
		return -EFAULT;
    }
    cur_secret_byte = *(char *)addr;
	return 8;
}

static struct proc_ops kernel_mem_scanner_proc_ops = {
	.proc_read = tool_read_op,
	.proc_write = tool_write_op,
};
static struct proc_dir_entry *proc_dir;
static uint64_t *test_addr; 

static int __init custom_init(void) {
    printk(KERN_INFO "PWSC Kernel Mem Scanner Hello :)");

    // Install proc endpoint for  userland 
    proc_dir = proc_mkdir("mem_scanner_tool", NULL);
    proc_create("scan_mem", 0666, proc_dir, &kernel_mem_scanner_proc_ops);

    // Insert 0xdeadbeef at address to verify module is working with userland
    test_addr = kmalloc(sizeof(uint64_t), GFP_KERNEL); 
    *test_addr = 0xdeadbeef; 

    printk(KERN_INFO "Test addr: 0x%llx %p\n", (uint64_t)test_addr, test_addr);

    return 0;
}

static void __exit custom_exit(void) {
    printk(KERN_INFO "PWSC Kernel Mem Scanner Goodbye :(");

    proc_remove(proc_dir);
    kfree(test_addr);
}


module_init(custom_init);
module_exit(custom_exit);
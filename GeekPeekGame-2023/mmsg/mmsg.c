#include <asm/errno.h>
#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#define BUILD_BUG_ON_MSG                                                       \
    {}

#define DEVICE_NAME "mmsg"
#define MMSG_DATA_MAX 1024
#define MMSG_DESC_LEN 16
#define SUCCESS 0

#define MMSG_ALLOC 0x1111111
#define MMSG_COPY 0x2222222
#define MMSG_RECV 0x3333333
#define MMSG_UPDATE 0x4444444
#define MMSG_PUT_DESC 0x5555555
#define MMSG_GET_DESC 0x6666666

struct mmsg_head {
        char description[16];
        struct list_head list;
};

struct mmsg {
        unsigned int token;
        int size;
        char *data;
        struct list_head list;
};

struct mmsg_arg {
        unsigned long token;
        int top;
        int size;
        char *data; 
};

static struct mmsg_head *mmsg_head;

int add_mmsg(unsigned int token, char *data, int size) {
    int ret = SUCCESS;
    struct mmsg *m;

    m = kmalloc(sizeof(struct mmsg), GFP_KERNEL);
    if (m == NULL) {
        ret = -ENOMEM;
        goto err_out;
    }
    m->token = token;
    if (size > MMSG_DATA_MAX || size <= 0) {
        ret = -EINVAL;
        goto size_err_out;
    }
    m->size = size;
    m->data = kmalloc(size, GFP_KERNEL);
    if (m->data == NULL) {
        ret = -ENOMEM;
        goto size_err_out;
    }
    copy_from_user(m->data, (void __user *)data, size);
    list_add(&m->list, &mmsg_head->list);
    return ret;
size_err_out:
    kfree(m);
err_out:
    return ret;
}

struct mmsg *find_mmsg(unsigned int token) {
    struct mmsg *msg = NULL;
    list_for_each_entry(msg, &mmsg_head->list, list) {
        if (msg->token == token) {
            return msg;
        }
    }
    msg = NULL;
    return msg;
}

static noinline long module_ioctl(struct file *file, unsigned int cmd,
                                  unsigned long u_arg) {
    long ret = SUCCESS;
    struct mmsg *m;
    struct mmsg_arg arg;
    char *tmp = NULL;
    memset(&arg, 0, sizeof(arg));
    copy_from_user(&arg, (void __user *)u_arg, sizeof(arg));
    switch (cmd) {
    case MMSG_ALLOC: 
        ret = add_mmsg(arg.token, arg.data, arg.size);
        printk(KERN_INFO "mmsg add\n");
        break;
    case MMSG_COPY: 
        if (arg.top) {
            m = list_entry(&mmsg_head->list, struct mmsg, list);
        } else {
            m = find_mmsg(arg.token);
        }
        if (m == NULL || arg.size > m->size || arg.size <= 0) {
            ret = -EINVAL;
            break;
        }
        printk(KERN_INFO "mmsg copy\n");
        ret = copy_to_user((void __user *)arg.data, m->data, arg.size);
        break;
    case MMSG_RECV: 
        if (arg.top) {
            m = list_entry(&mmsg_head->list, struct mmsg, list);
        } else {
            m = find_mmsg(arg.token);
        }
        if (m == NULL || arg.size > m->size || arg.size <= 0) {
            ret = -EINVAL;
            break;
        }
        printk(KERN_INFO "mmsg recv\n");
        copy_to_user((void __user *)arg.data, m->data, arg.size);
        list_del(&m->list);
        kfree(m->data);
        kfree(m);
        break;
    case MMSG_UPDATE: 
        if (arg.top) {
            m = list_entry(&mmsg_head->list, struct mmsg, list);
        } else {
            m = find_mmsg(arg.token);
        }
        if (m == NULL || arg.size > MMSG_DATA_MAX || arg.size <= 0) {
            ret = -EINVAL;
            break;
        }
        kfree(m->data);
        m->size = arg.size;
        tmp = kmalloc(arg.size, GFP_KERNEL);
        if (tmp == NULL) {
            ret = -ENOMEM;
            break;
        }
        m->data = tmp;
        printk(KERN_INFO "mmsg update\n");
        copy_from_user(m->data, (void __user *)arg.data, arg.size);
        break;
    case MMSG_PUT_DESC: 
        copy_from_user(&mmsg_head->description, (void __user *)arg.data,
                           MMSG_DESC_LEN);
        break;
    case MMSG_GET_DESC:
        copy_to_user((void __user *)arg.data, &mmsg_head->description,
                         MMSG_DESC_LEN);
            ret = -EFAULT;
    }

    return SUCCESS;
}

static int module_open(struct inode *inode, struct file *file) {
    printk(KERN_INFO "mmsg open\n");
    return SUCCESS;
}

static int module_close(struct inode *inode, struct file *file) {
    kfree(mmsg_head);
    return SUCCESS;
}

static struct file_operations module_fops = {
    .open = module_open,
    .release = module_close,
    .unlocked_ioctl = module_ioctl,
};

static struct miscdevice mmsg_device;

static int __init mmsg_module_init(void) {

    mmsg_device.minor = MISC_DYNAMIC_MINOR;
    mmsg_device.name = DEVICE_NAME;
    mmsg_device.fops = &module_fops;
    misc_register(&mmsg_device);
    mmsg_head = kmalloc(sizeof(struct mmsg_head), GFP_KERNEL);
    strncpy(mmsg_head->description, DEVICE_NAME "-mmsg_head", 15);
    INIT_LIST_HEAD(&mmsg_head->list);
    printk(KERN_INFO "Hello, World!\n");

    return SUCCESS;
}

static void __exit mmsg_module_exit(void) {
    misc_deregister(&mmsg_device);
    printk(KERN_INFO "Goodbye, World!\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Niebelungen");
MODULE_DESCRIPTION("ez kernel challenge");
MODULE_VERSION("1.0");

module_init(mmsg_module_init);
module_exit(mmsg_module_exit);

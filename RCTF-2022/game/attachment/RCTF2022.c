#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include<linux/errno.h>
#include<linux/file.h>
#include<linux/fs.h>
#include<linux/miscdevice.h>
#include<linux/module.h>
#include<linux/slab.h>
typedef struct Options{
	char *magic;
	char *fortune;
	long money;
};
static const char* key_list[] = {
	"flag",
	"fortune",
	"money",
	NULL,
};
typedef struct Maind{
	unsigned long id;
	char username[0x20];
	void *cur;
	void *prv;
	int random;
};

#define   MAJOR_NUM 250

struct mycdev
{
    int len;
    unsigned   char buffer[50];
    struct   cdev cdev;
};

MODULE_LICENSE("GPL");
static dev_t   dev_num = {0};
struct mycdev *gcd;
struct class *cls;
static int ndevices = 1;
module_param(ndevices, int, 0644);
MODULE_PARM_DESC(ndevices, "The number of devices for register.\n");

struct Maind* initMaind(void){
	struct Maind *fc;
	fc = kzalloc(sizeof(struct Maind), GFP_KERNEL);
	if (!fc)
		return NULL;
	return fc;
}
static int hhoge_open(struct inode *inode, struct file *file)
{
    struct Maind* context = initMaind();
	if(context==NULL){
		printk("g_context fail");
		return  -ENOMEM;
	}
	file->private_data = context;
    return 0;
}

static ssize_t   hhoge_read(struct file *file, char   __user *ubuf,   size_t
size, loff_t *ppos)
{
    struct Maind* context = file->private_data;
    if (context!=NULL && context->cur != NULL){
		copy_to_user(ubuf,(const void *)&(((struct Options*)context->cur)->magic),size>9? 9:size);
	}
    return 0;
}


static int hhoge_release(struct inode *inode, struct file *filp)
{
    filp->private_data = NULL;
	return 0;
}


static int lookup(const char*key){
	int i=-1;
	const char **p;
	int j = 0;
	for (p = key_list; *p!=NULL; p++,j++) {
		if (strcmp(*p, key) == 0){
			i = j;
			break;
		}
	}
	return i;
}
static int parse_string(struct Maind*context,const char*key,const char*value, size_t v_size){
	struct Options *opts = context->cur;
	char *string;
	int opt = -1;
	if (!opts){
		return -1;
	}
	if (value) {
		string = kmemdup_nul(value, v_size, GFP_KERNEL);
		if (!string)
			return -1;
	}
	opt = lookup(key);
	switch (opt) {
		case 0:
			kfree(opts->magic);
			opts->magic = string;
			string = NULL;
			break;
		case 1:
			opts->fortune = "lucky";
			break;
		case 2:
			opts->money += (long)string;
			break;
	}
	kfree(string);
	return 0;
}

void change(struct Maind*context,char*arg){
	char *options = arg, *key;
	if (!options)
		return;
	printk("change");
	while ((key = strsep(&options, ",")) != NULL) {
		if (*key) {
			size_t v_len = 0;
			char *value = strchr(key, '=');
			if (value) {
				if (value == key)
					continue;
				*value++ = 0;
				v_len = strlen(value);
				if (v_len > 9)
					continue;
			}
			int ret = parse_string(context,key, value, v_len);
			if (ret < 0)
				break;
		}
	}
}

void reborn(struct Maind* context){
	struct Options* new_opts ;
	if(context == NULL){
		return;
	}
	printk("reborn");
	new_opts = (struct Options*)kzalloc(sizeof(struct Options),GFP_KERNEL);
	context->prv = (void*)new_opts;
	memcpy(context->prv,context->cur,sizeof(struct Options));
	((struct Options*)context->cur)->fortune = "unlucky";
	((struct Options*)context->cur)->money = -114514;
	context->id++;
}
void delMaind(struct Maind* context){
	struct Options* cur;
	struct Options* prv;
	if(context == NULL){
		return;
	}
	printk("die\n");

	cur = (struct Options*)context->cur;
	prv = (struct Options*)context->prv;
	
	if (cur!=NULL){
		kfree(cur->magic);
		cur->magic = NULL;
		kfree(cur);
		context->cur = NULL;
	}
	if (prv!=NULL){
		kfree(prv->magic);
		prv->magic = NULL;
		kfree(prv);
		context->prv = NULL;
	}

	kfree(context);
}

long hhoge_unlocked_ioctl(struct file *file,   unsigned int cmd,
    unsigned   long arg)
{
    struct Maind* context = file->private_data;
	if(context==NULL)
		return -1;
	
	struct Options* opts;
	char tmp[0x20];
	copy_from_user(tmp,arg,sizeof(tmp));
	switch(cmd){
		case 0:
			printk("born");
			opts = (struct Options*)kzalloc(sizeof(struct Options),GFP_KERNEL);
			context->cur = (struct Options*)opts;
			((struct Options*)context->cur)->fortune = "ordinary";
			context->id = 0;
			memcpy(context->username,tmp,0x20);
			break;
		case 1:
			reborn(context);
			break;
		case 114:
			change(context,tmp);
			break;
		case 22:
			delMaind(context);
			file->private_data = NULL;

	}
	return 0;
}

static const struct file_operations fifo_operations = {
    .owner = THIS_MODULE,
    .open = hhoge_open,
    .read = hhoge_read,
    .release = hhoge_release,
    .unlocked_ioctl = hhoge_unlocked_ioctl,
};

int __init hhoge_init(void)
{
    int i = 0;
    int n = 0;
    int ret;

    struct device *device;
    gcd = kzalloc(ndevices* sizeof(struct mycdev), GFP_KERNEL);

    if(!gcd){
        return -ENOMEM;
    }

    dev_num = MKDEV(MAJOR_NUM, 0);

    ret = register_chrdev_region(dev_num,ndevices,"game");
    if(ret < 0){
        ret =alloc_chrdev_region(&dev_num,0,ndevices,"game");
        if(ret < 0){
            printk("Fail to register_chrdev_region\n");
            goto err_register_chrdev_region;
        }
    }
    cls = class_create(THIS_MODULE, "game");
    if(IS_ERR(cls)){
        ret = PTR_ERR(cls);
        goto err_class_create;
    }
    for(n = 0;n < ndevices;n++)
    {
        cdev_init(&gcd[n].cdev,&fifo_operations);
        ret = cdev_add(&gcd[n].cdev,dev_num + n,1);
        if (ret < 0)
        {
            goto err_cdev_add;
        }
        device = device_create(cls,NULL,dev_num +n,NULL,"game");
        if(IS_ERR(device)){
                ret = PTR_ERR(device);
                goto err_device_create;
        }
    }
    return   0;
err_device_create:
    for(i = 0;i < n;i++)
    {
       device_destroy(cls,dev_num + i);
    }
err_cdev_add:
    for(i = 0;i < n;i++)
    {
       cdev_del(&gcd[i].cdev);
    }
err_class_create:
    unregister_chrdev_region(dev_num,ndevices);
err_register_chrdev_region:
    return   ret;
}
void __exit hhoge_exit(void)
{
    int i;
    for(i = 0;i < ndevices;i++)
    {
        device_destroy(cls,dev_num + i); 
    }
    class_destroy(cls);
    for(i = 0;i < ndevices;i++)
    {
       cdev_del(&gcd[i].cdev);
    } 
    unregister_chrdev_region(dev_num,ndevices);
    return;
}
module_init(hhoge_init);
module_exit(hhoge_exit);

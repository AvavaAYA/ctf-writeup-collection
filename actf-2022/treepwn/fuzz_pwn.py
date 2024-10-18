#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian

from lianpwn import *
import sys

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux", "sp", "-h", "-l", "120"]

LOCAL = 1
filename = "./pwn"
if LOCAL:
    io = process(filename)
else:
    remote_service = ""
    remote_service = remote_service.strip().split(":")
    io = remote(remote_service[0], int(remote_service[1]))
elf = ELF(filename, checksec=False)
libc = ELF(elf.libc.path, checksec=False)


def ru(a, drop=False):
    return io.recvuntil(a, drop)


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
    ru(b"Your choice > ")
    sl(i2b(choice))


def add(x0, y0, name):
    cmd(0)
    ru(b"new element x-coordinate value: ")
    sl(i2b(x0))
    ru(b"new element y-coordinate value: ")
    sl(i2b(y0))
    ru(b"new element name: ")
    s(name.ljust(32, b"\x00"))


def delet(x0, y0):
    cmd(1)
    ru(b"want element x-coordinate value: ")
    sl(i2b(x0))
    ru(b"want element y-coordinate value: ")
    sl(i2b(y0))


def edit(x0, y0, name):
    cmd(2)
    ru(b"want element x-coordinate value: ")
    sl(i2b(x0))
    ru(b"want element y-coordinate value: ")
    sl(i2b(y0))
    ru(b"input the edited name: ")
    s(name.ljust(32, b"\x00"))


def show(x0, y0):
    cmd(3)
    ru(b"want element x-coordinate value: ")
    sl(i2b(x0))
    ru(b"want element y-coordinate value: ")
    sl(i2b(y0))


def query(xld, yld, xru, yru):
    cmd(4)
    ru(b"left-down position x-coordinate value: ")
    sl(i2b(xld))
    ru(b"left-down position y-coordinate value: ")
    sl(i2b(yld))
    ru(b"right-up position x-coordinate value: ")
    sl(i2b(xru))
    ru(b"right-up position y-coordinate value: ")
    sl(i2b(yru))


def fuzz():
    f = open("./log.txt", "w")
    for i in range(0x1000):
        if i % 10 == 0:
            a = randint(0, 8)
            b = randint(0, 8)
            add(a, b, i2b(i))
            data0 = ru(b"Choice Table")
            if b"two many" in data0:
                break
            f.write(" add({},{},i2b({}))\n".format(a, b, i))
        elif i % 2 == 0:
            a = randint(0, 8)
            b = randint(0, 8)
            delet(a, b)
            data0 = rl()
            if b"not exists" in data0:
                continue
            f.write(" delet({},{})\n".format(a, b))
        else:
            continue
            a = randint(0, 8)
            b = randint(0, 8)
            c = randint(0, 8)
            d = randint(0, 8)
            query(a, b, c, d)
            data0 = ru(b"Choice Table")
            if b"totally 0 elements" in data0:
                continue
            elif b"\x55" in data0:
                f.write(" query({},{},{},{})\n".format(a, b, c, d))
                break
            elif b"\x56" in data0:
                f.write(" query({},{},{},{})\n".format(a, b, c, d))
                break
    f.close()


fuzz()

"""
while True:
    try:

        ia()
    except:
        io.close()
        if LOCAL:
            io = process(filename)
        else:
            io = remote(remote_service[0], int(remote_service[1]))
"""

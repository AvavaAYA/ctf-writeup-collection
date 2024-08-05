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
    ru(b"*> ")
    sl(i2b(choice))


def add(size1, size2, data):
    cmd(1)
    ru(b"how many guavas: ")
    sl(i2b(size1))
    ru(b"guavset: ")
    sl(i2b(size2))
    ru(b"guavas: ")
    s(data)


add(0x80, 0x70, b"aaa")

ia()

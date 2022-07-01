#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *
import random

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

# remote_service = ""
# remote_service = remote_service.strip().split(":")
# p = remote(remote_service[0], int(remote_service[1]))
filename = "./pwn"
p = process(filename)
e = ELF(filename, checksec=False)
l = ELF(e.libc.path, checksec=False)

rl = lambda a=False : p.recvline(a)
ru = lambda a,b=True : p.recvuntil(a,b)
rn = lambda x : p.recvn(x)
sn = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
irt = lambda : p.interactive()
dbg = lambda text=None : gdb.attach(p, text)
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
i2b = lambda c : str(c).encode()
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))
def debugPID():
	lg("p.pid")
	input()
	pass
def cmd(choice):
	ru(b'Your choice > ')
	sl(i2b(choice))
def insert(x0, y0, name):
	cmd(0)
	ru(b'new element x-coordinate value: ')
	sl(i2b(x0))
	ru(b'new element y-coordinate value: ')
	sl(i2b(y0))
	ru(b'new element name: ')
	sn(name.ljust(32, b'\x00'))
def delete(x0, y0):
	cmd(1)
	ru(b'want element x-coordinate value: ')
	sl(i2b(x0))
	ru(b'want element y-coordinate value: ')
	sl(i2b(y0))
def edit(x0, y0, name):
	cmd(2)
	ru(b'want element x-coordinate value: ')
	sl(i2b(x0))
	ru(b'want element y-coordinate value: ')
	sl(i2b(y0))
	ru(b'input the edited name: ')
	sn(name.ljust(32, b'\x00'))
def show(x0, y0):
	cmd(3)
	ru(b'want element x-coordinate value: ')
	sl(i2b(x0))
	ru(b'want element y-coordinate value: ')
	sl(i2b(y0))
def query(xld, yld, xru, yru):
	cmd(4)
	ru(b'left-down position x-coordinate value: ')
	sl(i2b(xld))
	ru(b'left-down position y-coordinate value: ')
	sl(i2b(yld))
	ru(b'right-up position x-coordinate value: ')
	sl(i2b(xru))
	ru(b'right-up position y-coordinate value: ')
	sl(i2b(yru))

insert(0, 10, b"1010101")
insert(0, 11, b"asada")

debugPID()
irt()

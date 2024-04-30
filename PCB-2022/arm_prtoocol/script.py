#!/usr/bin/python2

from pwn import *

p = remote('192.168.1.104', 8888)

# size: for mode 'add'
# index: for mode 'delete', 'edit', 'show'
# data: for edit
def gen_payload(mode='add', size=0, index=0, data=''):
	assert mode in ['show', 'delete', 'edit', 'add']
	if mode == 'add': assert 0 < size <= 112
	else: assert size == 0
	assert len(data) <= 48

	payload = p32(0x11451400) # 0-4
	checksum = size ^ index
	for i in data:
		if i == '\x00': break
		checksum ^= ord(i)
	payload += p32(checksum) # 4-8
	payload += p32(size) # 8-12
	payload += p32(index) # 12-16
	payload += data.ljust(56, '\x00') # 16-72
	if mode == 'delete': payload += '\x01' # 72
	else: payload += '\x00'
	if mode == 'show': payload += '\x01' # 73
	else: payload += '\x00'
	if mode == 'edit': payload += '\x01' # 74
	else: payload += '\x00'
	payload += 'AbZXR\x00' # 75-81
	return payload

def skip():
	p.recvuntil('>\n')

def Add(size):
	skip()
	p.send(gen_payload('add', size=size))

def Show(index):
	skip()
	p.send(gen_payload('show', index=index))

def Delete(index):
	skip()
	p.send(gen_payload('delete', index=index))

def Edit(index, content):
	skip()
	p.send(gen_payload('edit', data=content))


context.log_level = 'debug'

Add(0x10)
Edit(0, '123456')
Show(0)
Delete(0)

p.interactive()
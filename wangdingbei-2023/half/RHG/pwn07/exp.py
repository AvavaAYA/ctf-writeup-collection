#!/usr/bin/python3
#-*- coding: utf-8 -*-
#  author: @eastXueLian

from pwn import *
import random
import sys

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

LOCAL = 1
filename = "./pwn"
if LOCAL:
    pass
    #  io = process(filename)
else:
    remote_service = ""
    remote_service = remote_service.strip().split(":")
    pass
    #  io = remote(remote_service[0], int(remote_service[1]))
#  elf = ELF(filename, checksec=False)
#  libc = ELF(elf.libc.path, checksec=False)


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

answer = []
keys = ['W', 'A', 'S', 'D']

for i0 in range(4):
    for i1 in range(4):
        for i2 in range(4):
            for i3 in range(4):
                for i4 in range(4):
                    for i5 in range(4):
                        for i6 in range(4):
                            for i7 in range(4):
                                for i8 in range(4):
                                    for i9 in range(4):
                                        answer.append((keys[i0] + keys[i1] + keys[i2] + keys[i3] + keys[i4] + keys[i5] + keys[i6] + keys[i7] + keys[i8] + keys[i9] ).encode())

for try_ans in answer:
    #  io = remote(remote_service[0], int(remote_service[1]))
    io = process(filename)
    try:
        ru(b'please input the way you want go')
        s(try_ans)
        rn(1)
        ia()
    except Exception as e:
        io.close()
        continue
    print(try_ans)

ia()

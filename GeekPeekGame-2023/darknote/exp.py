#!/usr/bin/python3
#-*- coding: utf-8 -*-
#  author: @eastXueLian

from pwn import *
import sys

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'sp', '-h', '-l', '120']

LOCAL = 1
filename = "./darknote"
if LOCAL:
    io = process(filename)
else:
    remote_service = ""
    remote_service = remote_service.strip().split(":")
    io = remote(remote_service[0], int(remote_service[1]))
elf = ELF(filename, checksec=False)
libc = ELF(elf.libc.path, checksec=False)

rl      = lambda a=False    : io.recvline(a)
ru      = lambda a, b=True  : io.recvuntil(a, b)
rn      = lambda x          : io.recvn(x)
s       = lambda x          : io.send(x)
sl      = lambda x          : io.sendline(x)
sa      = lambda a, b       : io.sendafter(a, b)
sla     = lambda a, b       : io.sendlineafter(a, b)
ia      = lambda            : io.interactive()
dbg     = lambda text=None  : gdb.attach(io, text)
lg      = lambda s          : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
i2b     = lambda c          : str(c).encode()
u32_ex  = lambda data       : u32(data.ljust(4, b'\x00'))
u64_ex  = lambda data       : u64(data.ljust(8, b'\x00'))


def debugPID():
    if LOCAL:
        lg("io.pid")
        input()
    pass

debugPID()

ia()

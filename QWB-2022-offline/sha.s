	.file	"test.c"
	.intel_syntax noprefix
	.text
	.globl	sha256
	.type	sha256, @function
sha256:
	endbr32
	call	__x86.get_pc_thunk.ax
	add	eax, OFFSET FLAT:_GLOBAL_OFFSET_TABLE_
	push	ebp
	mov	ebp, esp
	push	edi
	push	esi
	push	ebx
	sub	esp, 348
	mov	ecx, DWORD PTR 12[ebp]
	mov	DWORD PTR -344[ebp], eax
	mov	eax, 448
	lea	edi, 0[0+ecx*8]
	mov	edx, edi
	and	edx, 504
	cmp	edx, 447
	jle	.L30
	mov	eax, 960
.L30:
	sub	eax, edx
	sar	eax, 3
	add	eax, ecx
	mov	DWORD PTR -288[ebp], eax
	add	eax, 8
	mov	DWORD PTR -292[ebp], eax
	mov	eax, DWORD PTR -288[ebp]
	lea	ebx, 23[eax]
	mov	eax, esp
	mov	edx, ebx
	and	ebx, -4096
	sub	eax, ebx
	and	edx, -16
	mov	ebx, eax
.L4:
	cmp	esp, ebx
	je	.L5
	sub	esp, 4096
	or	DWORD PTR 4092[esp], 0
	jmp	.L4
.L5:
	and	edx, 4095
	sub	esp, edx
	test	edx, edx
	je	.L6
	or	DWORD PTR -4[esp+edx], 0
.L6:
	mov	DWORD PTR -284[ebp], esp
	mov	ebx, ecx
.L7:
	cmp	DWORD PTR -288[ebp], ebx
	jbe	.L32
	mov	eax, DWORD PTR -284[ebp]
	mov	BYTE PTR [eax+ebx], 0
	inc	ebx
	jmp	.L7
.L32:
	test	ecx, ecx
	je	.L9
	mov	ebx, DWORD PTR 8[ebp]
	mov	esi, DWORD PTR -284[ebp]
	lea	eax, [ebx+ecx]
	mov	edx, eax
	jmp	.L10
.L9:
	mov	eax, DWORD PTR -284[ebp]
	mov	esi, edi
	xor	edi, edi
	mov	BYTE PTR [eax+ecx], -128
	mov	eax, DWORD PTR -288[ebp]
	mov	ecx, 56
	add	eax, DWORD PTR -284[ebp]
	mov	DWORD PTR -288[ebp], eax
	jmp	.L11
.L10:
	cmp	edx, ebx
	je	.L9
	mov	al, BYTE PTR [ebx]
	inc	esi
	inc	ebx
	mov	BYTE PTR -1[esi], al
	jmp	.L10
.L11:
	mov	eax, esi
	mov	edx, edi
	shrd	eax, edi, cl
	shr	edx, cl
	test	cl, 32
	cmovne	eax, edx
	sub	ecx, 8
	mov	ebx, eax
	mov	eax, DWORD PTR -288[ebp]
	inc	DWORD PTR -288[ebp]
	mov	BYTE PTR [eax], bl
	cmp	ecx, -8
	jne	.L11
	xor	eax, eax
	lea	edi, -280[ebp]
	mov	ecx, 64
	mov	DWORD PTR -332[ebp], 1541459225
	rep stosd
	mov	eax, DWORD PTR -292[ebp]
	mov	DWORD PTR -328[ebp], 528734635
	mov	DWORD PTR -324[ebp], -1694144372
	mov	DWORD PTR -320[ebp], 1359893119
	and	eax, -64
	add	eax, DWORD PTR -284[ebp]
	mov	DWORD PTR -348[ebp], eax
	lea	eax, -88[ebp]
	mov	DWORD PTR -316[ebp], -1521486534
	mov	DWORD PTR -304[ebp], 1013904242
	mov	DWORD PTR -308[ebp], -1150833019
	mov	DWORD PTR -312[ebp], 1779033703
	mov	DWORD PTR -352[ebp], eax
.L13:
	mov	edi, DWORD PTR -284[ebp]
	cmp	DWORD PTR -348[ebp], edi
	je	.L33
	xor	eax, eax
	xor	edx, edx
.L15:
	imul	ecx, eax, -8
	mov	edi, DWORD PTR -284[ebp]
	movzx	ebx, BYTE PTR [edi+eax]
	add	ecx, 24
	sal	ebx, cl
	mov	ecx, eax
	and	ecx, 3
	or	edx, ebx
	cmp	ecx, 3
	jne	.L14
	mov	ecx, eax
	sar	ecx, 2
	mov	DWORD PTR -280[ebp+ecx*4], edx
	xor	edx, edx
.L14:
	inc	eax
	cmp	eax, 64
	jne	.L15
	lea	edx, -280[ebp]
.L16:
	mov	eax, DWORD PTR 4[edx]
	mov	ebx, DWORD PTR 56[edx]
	add	edx, 4
	mov	esi, eax
	mov	ecx, eax
	shr	eax, 3
	ror	esi, 7
	rol	ecx, 14
	xor	ecx, esi
	mov	esi, ebx
	xor	eax, ecx
	mov	ecx, DWORD PTR 32[edx]
	add	ecx, DWORD PTR -4[edx]
	rol	esi, 15
	add	eax, ecx
	mov	ecx, ebx
	shr	ebx, 10
	rol	ecx, 13
	xor	ecx, esi
	xor	ecx, ebx
	add	ecx, eax
	mov	DWORD PTR 60[edx], ecx
	cmp	DWORD PTR -352[ebp], edx
	jne	.L16
	mov	eax, DWORD PTR -332[ebp]
	mov	edi, DWORD PTR -320[ebp]
	xor	ebx, ebx
	mov	edx, DWORD PTR -312[ebp]
	mov	DWORD PTR -336[ebp], eax
	mov	eax, DWORD PTR -328[ebp]
	mov	DWORD PTR -300[ebp], eax
	mov	eax, DWORD PTR -324[ebp]
	mov	DWORD PTR -296[ebp], eax
	mov	eax, DWORD PTR -316[ebp]
	mov	DWORD PTR -340[ebp], eax
	mov	eax, DWORD PTR -304[ebp]
	mov	DWORD PTR -292[ebp], eax
	mov	eax, DWORD PTR -308[ebp]
	mov	DWORD PTR -288[ebp], eax
.L17:
	mov	eax, edi
	mov	ecx, edi
	mov	esi, DWORD PTR -280[ebp+ebx*4]
	ror	ecx, 11
	ror	eax, 6
	xor	eax, ecx
	mov	ecx, edi
	rol	ecx, 7
	xor	ecx, eax
	mov	eax, DWORD PTR -344[ebp]
	add	esi, DWORD PTR k@GOTOFF[eax+ebx*4]
	mov	eax, edi
	inc	ebx
	add	ecx, esi
	mov	esi, DWORD PTR -296[ebp]
	not	eax
	and	eax, DWORD PTR -300[ebp]
	and	esi, edi
	xor	eax, esi
	mov	esi, edx
	add	eax, ecx
	mov	ecx, edx
	ror	esi, 13
	add	eax, DWORD PTR -336[ebp]
	ror	ecx, 2
	xor	esi, ecx
	mov	ecx, edx
	rol	ecx, 10
	xor	esi, ecx
	mov	ecx, DWORD PTR -288[ebp]
	xor	ecx, DWORD PTR -292[ebp]
	mov	DWORD PTR -336[ebp], esi
	and	ecx, edx
	mov	esi, DWORD PTR -288[ebp]
	and	esi, DWORD PTR -292[ebp]
	xor	ecx, esi
	mov	esi, DWORD PTR -336[ebp]
	add	esi, ecx
	mov	ecx, DWORD PTR -340[ebp]
	add	esi, eax
	add	ecx, eax
	mov	eax, DWORD PTR -292[ebp]
	mov	DWORD PTR -340[ebp], eax
	mov	eax, DWORD PTR -300[ebp]
	mov	DWORD PTR -336[ebp], eax
	cmp	ebx, 64
	je	.L34
	mov	eax, DWORD PTR -296[ebp]
	mov	DWORD PTR -296[ebp], edi
	mov	edi, ecx
	mov	DWORD PTR -300[ebp], eax
	mov	eax, DWORD PTR -288[ebp]
	mov	DWORD PTR -288[ebp], edx
	mov	edx, esi
	mov	DWORD PTR -292[ebp], eax
	jmp	.L17
.L34:
	mov	ebx, DWORD PTR -288[ebp]
	add	DWORD PTR -324[ebp], edi
	add	DWORD PTR -304[ebp], ebx
	mov	edi, DWORD PTR -296[ebp]
	mov	ebx, DWORD PTR -292[ebp]
	add	DWORD PTR -312[ebp], esi
	add	DWORD PTR -308[ebp], edx
	add	DWORD PTR -316[ebp], ebx
	add	DWORD PTR -320[ebp], ecx
	add	DWORD PTR -328[ebp], edi
	add	DWORD PTR -332[ebp], eax
	add	DWORD PTR -284[ebp], 64
	jmp	.L13
.L33:
	mov	edi, DWORD PTR 16[ebp]
	mov	eax, DWORD PTR -312[ebp]
	bswap	eax
	mov	DWORD PTR [edi], eax
	mov	eax, DWORD PTR -308[ebp]
	bswap	eax
	mov	DWORD PTR 4[edi], eax
	mov	eax, DWORD PTR -304[ebp]
	bswap	eax
	mov	DWORD PTR 8[edi], eax
	mov	eax, DWORD PTR -316[ebp]
	bswap	eax
	mov	DWORD PTR 12[edi], eax
	mov	eax, DWORD PTR -320[ebp]
	bswap	eax
	mov	DWORD PTR 16[edi], eax
	mov	eax, DWORD PTR -324[ebp]
	bswap	eax
	mov	DWORD PTR 20[edi], eax
	mov	eax, DWORD PTR -328[ebp]
	bswap	eax
	mov	DWORD PTR 24[edi], eax
	mov	eax, DWORD PTR -332[ebp]
	bswap	eax
	mov	DWORD PTR 28[edi], eax
	lea	esp, -12[ebp]
	pop	ebx
	pop	esi
	pop	edi
	pop	ebp
	ret
	.size	sha256, .-sha256
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC1:
	.string	"%02x"
.LC0:
	.string	"0123456789abcdef"
	.section	.text.startup,"ax",@progbits
	.globl	main
	.type	main, @function
main:
	endbr32
	lea	ecx, 4[esp]
	and	esp, -16
	push	DWORD PTR -4[ecx]
	push	ebp
	mov	ebp, esp
	push	edi
	push	esi
	push	ebx
	push	ecx
	lea	eax, -262144[esp]
.LPSRL0:
	sub	esp, 4096
	or	DWORD PTR [esp], 0
	cmp	esp, eax
	jne	.LPSRL0
	sub	esp, 92
	call	__x86.get_pc_thunk.bx
	add	ebx, OFFSET FLAT:_GLOBAL_OFFSET_TABLE_
	mov	eax, DWORD PTR 4[ecx]
	push	0
	lea	edi, -262196[ebp]
	push	0
	lea	esi, .LC0@GOTOFF[ebx]
	push	DWORD PTR [eax]
	call	open@PLT
	add	esp, 12
	lea	edx, -262168[ebp]
	push	262144
	push	edx
	push	eax
	mov	DWORD PTR -262236[ebp], edx
	call	read@PLT
	xor	eax, eax
	mov	ecx, 7
	add	esp, 12
	rep stosd
	lea	eax, -262200[ebp]
	mov	DWORD PTR -262200[ebp], 0
	lea	edi, -262217[ebp]
	push	eax
	push	14472
	push	DWORD PTR -262236[ebp]
	mov	DWORD PTR -262240[ebp], eax
	call	sha256
	mov	eax, DWORD PTR -262240[ebp]
	mov	ecx, 17
	add	esp, 16
	rep movsb
	lea	esi, .LC1@GOTOFF[ebx]
	mov	edi, eax
.L36:
	push	eax
	inc	edi
	push	eax
	movzx	eax, BYTE PTR -1[edi]
	push	eax
	push	esi
	call	printf@PLT
	mov	cl, BYTE PTR -1[edi]
	add	esp, 12
	push	2
	mov	eax, ecx
	and	ecx, 15
	shr	al, 4
	movzx	eax, al
	mov	al, BYTE PTR -262217[ebp+eax]
	mov	BYTE PTR -262219[ebp], al
	mov	al, BYTE PTR -262217[ebp+ecx]
	mov	BYTE PTR -262218[ebp], al
	lea	eax, -262219[ebp]
	push	eax
	push	1
	call	write@PLT
	add	esp, 16
	cmp	edi, DWORD PTR -262236[ebp]
	jne	.L36
	lea	esp, -16[ebp]
	xor	eax, eax
	pop	ecx
	pop	ebx
	pop	esi
	pop	edi
	pop	ebp
	lea	esp, -4[ecx]
	ret
	.size	main, .-main
	.section	.rodata
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
	.section	.text.__x86.get_pc_thunk.ax,"axG",@progbits,__x86.get_pc_thunk.ax,comdat
	.globl	__x86.get_pc_thunk.ax
	.hidden	__x86.get_pc_thunk.ax
	.type	__x86.get_pc_thunk.ax, @function
__x86.get_pc_thunk.ax:
	mov	eax, DWORD PTR [esp]
	ret
	.section	.text.__x86.get_pc_thunk.bx,"axG",@progbits,__x86.get_pc_thunk.bx,comdat
	.globl	__x86.get_pc_thunk.bx
	.hidden	__x86.get_pc_thunk.bx
	.type	__x86.get_pc_thunk.bx, @function
__x86.get_pc_thunk.bx:
	mov	ebx, DWORD PTR [esp]
	ret
	.ident	"GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 4
	.long	 1f - 0f
	.long	 4f - 1f
	.long	 5
0:
	.string	 "GNU"
1:
	.align 4
	.long	 0xc0000002
	.long	 3f - 2f
2:
	.long	 0x3
3:
	.align 4
4:

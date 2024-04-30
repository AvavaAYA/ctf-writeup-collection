#!/usr/bin/python3

from pydoc import plain
from pwn import *
from random import randint
def gen_shellcode(p,q):
    context.arch = 'amd64'
    data_addr = 0x2000000
    
    p1 = p & ((2<<32)-1)
    p2 = (p>>32) & ((2<<32)-1)
    p3 = 0
    p4 = 0
    p5 = 0
    p6 = 0
    p7 = 0
    p8 = 0

    q1 = randint(2**31,2**32)
    q2 = randint(2**31,2**32)
    q3 = randint(2**31,2**32)
    q4 = randint(2**16,2**17)
    q5 = 0
    q6 = 0
    q7 = 0
    q8 = 0

    # p2 = randint(2**63,2**64)
    # p3 = randint(2**63,2**64)
    # p4 = randint(2**16,2**17)
    # q1 = randint(2**63,2**64)
    # q2 = randint(2**63,2**64)
    # q3 = randint(2**63,2**64)
    # q4 = randint(2**16,2**17)


    sc = asm(f'''
    nop
    nop
    nop
    nop
    mov dword ptr [{data_addr}], {p1}
    mov dword ptr [{data_addr + 4}], {p2}
    mov dword ptr [{data_addr + 8}], {p3}
    mov dword ptr [{data_addr + 12}], {p4}
    mov dword ptr [{data_addr + 16}], {p5}
    mov dword ptr [{data_addr + 20}], {p6}
    mov dword ptr [{data_addr + 24}], {p7}
    mov dword ptr [{data_addr + 28}], {p8}

    mov dword ptr [{data_addr + 32}], 	  {q1}
    mov dword ptr [{data_addr + 36}],  {q2}
    mov dword ptr [{data_addr + 40}],  {q3}
    mov dword ptr [{data_addr + 44}], {q4}
    mov dword ptr [{data_addr + 48}], {q5}
    mov dword ptr [{data_addr + 52}], {q6}
    mov dword ptr [{data_addr + 56}], {q7}
    mov dword ptr [{data_addr + 60}], {q8}
    ''')
    
    print("ans:", sc.hex())
    ans = sc.hex()

gen_shellcode(randint(2**253,2**254),randint(2**253,2**254))
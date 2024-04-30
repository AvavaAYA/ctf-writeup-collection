#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *

cli_script()
# set_remote_libc('libc.so.6')

context.log_level = "DEBUG"

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c: str(c).encode()
lg = lambda s: log.info("\033[1;31;40m %s --> 0x%x \033[0m" % (s, eval(s)))
debugB = lambda: input("\033[1m\033[33m[ATTACH ME]\033[0m")

import subprocess

subprocess.run(["musl-gcc", "./exp.c", "-static", "-masm=intel", "-o", "./exp"])


ia()

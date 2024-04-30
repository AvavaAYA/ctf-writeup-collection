#!/usr/bin/python3

from pwn import *
context.arch = "amd64"


with open("./my_shellcode", "wb") as fd:
    fd.write(payload)

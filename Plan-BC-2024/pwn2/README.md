---
date: 2024-07-20 09:11
challenge: pwn2
tags:
  - strfmt
  - close stdout
---

## pwn2

这道题第一眼看到以为是普通的 strfmt，没想到题目还把标准输出关了。不过好在提供了泄露栈地址的能力。因此即使没有 elf 和 libc 基地址，也能借助改栈上残留地址的末位，进而实现一定程度的任意地址写。

思路如下：

1. 泄露栈地址
2. 前期准备工作，包括构造溢出、布置指向 stdout 的指针
3. 篡改 stdout 指针到 stderr，重新获取输出
4. 有输出的情况下就常规打法了，记得 getshell 后要 `1>&2`

因为 elf 地址和 libc 地址都是未知的，因此需要爆破两次 $\frac{1}{16}$，还是可以接受的：

[exp.py](./exp.py)
---
date: 2024-08-26 11:24
challenge: speedpwn
tags:
  - fsop
  - scanf
---

不知道为什么总是忘记绕过 scanf 读入数字不改变原始数据的办法：

> [!IMPORTANT]
> 对于 `scanf("%d", &xxx)` 之类的读入都可能存在泄露，如果想保留原始数据又不影响后续输入（scanf 默认不刷新缓冲区，若有非法数据则会影响下次输入），
>
> **输入 `+` 即可**

难点在于泄露，题目提供了在 bss 段上往后溢出写、劫持 bss 段上一个 file 结构体指针、没有 PIE 三个能力，因此只需要泄露得到 libc 地址就能打 FSOP（或者改 `fileno` 和几个 ptr 实现任意地址读写）。

泄露在 simulate 功能里，scanf 的缓冲区中包含 libc 中的地址，

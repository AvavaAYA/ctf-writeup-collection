---
date: 2024-08-26 11:24
challenge: speedpwn
tags:
  - fsop
  - scanf
---

难点在于泄露，题目提供了在 bss 段上往后溢出写、劫持 bss 段上一个 file 结构体指针、没有 PIE 三个能力，因此只需要泄露得到 libc 地址就能打 FSOP（或者改 `fileno` 和几个 ptr 实现任意地址读写）。

泄露在 simulate 功能里，scanf 的缓冲区中包含 libc 中的地址，

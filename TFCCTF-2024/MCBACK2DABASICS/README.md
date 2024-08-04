---
date: 2024-08-04 21:54
challenge: MCBACK2DABASICS
tags:
  - double free
  - scanf
---

比较抽象的一道题：

Libc 版本很老，以至于没有 tcache，大小被限制在 fast_bin 内，可以考虑用 scanf 读入很长的数据来触发 fastbin 的合并获得一块 large bin；

一开始我想的是 house of roman，但是感觉太麻烦了，回到 io leak 上面：

泄漏 libc 后就是写 malloc hook：

[exp.py](./exp.py)

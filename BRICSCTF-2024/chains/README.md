---
date: 2024-10-07 08:54
challenge: chains
tags:
  - UAF
---

这道题包装得比较巧妙，可以看到一些「类型混淆」的思路。其中 chains 和 proxies 的删除是独立的，但是 chains 当中会储存对 proxies 的引用，源码见 [main.c](./src/main.c)。

在取得地址泄漏后可以伪造堆块并释放进 tcache 中，获得 chunk overlap。

在最终利用中我一开始想尝试 [House of Apple](https://eastxuelian.nebuu.la/glibc-simple#apple2-%E6%9D%BF%E5%AD%90)，但是发现 0x80 的堆块大小限制与乱七八糟的堆布局（我的问题）给布置带来了一些麻烦，最终回到泄漏 environ、劫持回栈上打 ROP：

[exp.py](./deploy/exp.py)

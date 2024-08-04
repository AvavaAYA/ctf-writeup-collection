---
date: 2024-08-04 21:06
challenge: GUARD-THE-BYPASS
tags:
  - tls
  - canary bypass
---

这是一道「栈溢出大量数据覆盖子线程 tls 中 canary」的题目：[问题：1）TLS 在什么位置 2）主线程与子线程的堆分配有什么不同](https://eastxuelian.nebuu.la/glibc-basics#%E9%97%AE%E9%A2%981tls-%E5%9C%A8%E4%BB%80%E4%B9%88%E4%BD%8D%E7%BD%AE-2%E4%B8%BB%E7%BA%BF%E7%A8%8B%E4%B8%8E%E5%AD%90%E7%BA%BF%E7%A8%8B%E7%9A%84%E5%A0%86%E5%88%86%E9%85%8D%E6%9C%89%E4%BB%80%E4%B9%88%E4%B8%8D%E5%90%8C)。

线程栈上 tls 的相对偏移是固定，利用代码见 [exp.py](./exp.py)。

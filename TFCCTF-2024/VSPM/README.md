---
date: 2024-08-04 21:56
challenge: VSPM
tags:
  - double free
---

有一些年代感；

可以越界写管理数组，打 double free 之后劫持 malloc hook：

[exp.py](./exp.py)

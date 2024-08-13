---
date: 2024-08-13 12:55
challenge: w4dup 2de
tags:
  - ret2dlresolve
  - dup
---

> 很难不吐槽我刚开始学习时的笔记写得很烂，这次找到 ret2dlresolve 愣是半天才看懂

这应该是比较公式化的一次解题了，后面 ROP 的思路也很直接：题目禁止了 `read(not 0)`，那把 0 close 掉再 open flag.txt 就行了，和 dup 好像没什么关系，不知道题目名字在说什么：

[exp.py](./exp.py)

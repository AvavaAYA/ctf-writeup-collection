---
date: 2024-10-10 23:22
challenge: stack_and_heap
tags:
  - double free
---

上古 2.23 的 UAF 题，malloc hook 的利用很简单，后面要找个 gadget 回到栈上事先布置好的地方打 ROP，注意还要用 openat 绕过对 open 的限制：

[exp.py](./exp.py)

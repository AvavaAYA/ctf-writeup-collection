---
data: 2024-10-30 15:28
challenge: pwn-04
tags:
  - UAF
---

裸的 UAF，打到 free hook 上再 setcontext 转去 orw：

[exp](exp.py)

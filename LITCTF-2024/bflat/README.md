---
date: 2024-08-13 12:47
challenge: How to Raise a Boring Vuln Flat
tags:
  - strfmt outof stack
  - burp
---

劫持 qsort 里的比较函数到 printf，进而使用格式化字符串完成泄露和回到 main 函数。

因为格式化字符串不在栈上，所以需要爆破：

[exp.py](./exp.py)

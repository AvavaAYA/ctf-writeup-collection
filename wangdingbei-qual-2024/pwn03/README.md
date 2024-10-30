---
data: 2024-10-30 18:24
challenge: pwn-03
tags:
  - jerryscript
  - unsolved
---

Jerryscript 的漏洞在 issue 列表里一搜一大堆，但看了一圈没一个好用的，等有空可以回来看看。这里先记录一下编译 / 调试：

```bash
git clone https://github.com/jerryscript-project/jerryscript.git
cd jerryscript
git checkout d7e21259
python ./tools/build.py --clean --compile-flag=-g --strip=off --lto=off --error-messages=on --logging=on --line-info=on --stack-limit=20
```

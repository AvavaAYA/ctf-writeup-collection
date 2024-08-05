---
date: 2024-07-29 06:44
challenge: shadow
tags:
  - heap
---

这道题的关键是泄漏堆地址，拿到异或 key 后的堆地址可以进行如下运算还原：

```python
def revese(key):
    key = key ^ ((key >> 12) & 0x000FFF000000)
    key = key ^ ((key >> 12) & 0x000000FFF000)
    key = key ^ ((key >> 12) & 0x000000000FFF)
    return key
```

解题脚本位于 [bin/exp.py](./bin/exp.py)

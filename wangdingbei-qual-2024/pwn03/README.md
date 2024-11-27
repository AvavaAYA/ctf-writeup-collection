---
data: 2024-10-30 18:24
challenge: pwn-03
tags:
  - jerryscript
---

这题埋了个洞，拿到题目时还是应该 bindiff 一下。

- poc

```javascript
let arr = new Array(8);
arr.pop();
print(arr);
```

## References

[网鼎杯青龙组的 PWN03 Jerryscript 题目](https://mp.weixin.qq.com/s/WwTRjkqfwesM0RYx3MVKmg) . *1nv0k3r*

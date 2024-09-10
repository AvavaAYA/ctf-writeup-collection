---
data: 2024-09-10 12:23
challenge: logger
tags:
  - CHOP
  - try-catch
---

异常处理，参考 [溢出漏洞在异常处理中的攻击利用手法-上](https://xz.aliyun.com/t/12967)

CHOP 指的是借助 Cpp 的 try-catch 机制 + 栈溢出等漏洞可以控制 RBP 并劫持控制流到其它 catch 块中，也可以借助该手段无视 canary 保护，基本原理如下：

1. `_Unwind_Resume` 函数中会根据栈帧恢复 RBP；
2. 同时会根据栈上的返回地址往上找上一层 catch 块，再通过 `_Unwind_Resume` 恢复执行上下文；
3. 因此就可以把返回地址溢出写成其它 try 块中的地址（因为不能下条指令和当前地址一样，所以通常写 `try_addr + 1`），控制流就能被劫持到对应的 catch块中。

回到题目，看到有个函数里面有 Hello，本来打算试试能不能把 rip 劫持上去输出点什么，结果直接进 shell 了：

[exp.py](./exp.py)

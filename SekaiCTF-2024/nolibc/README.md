---
date: 2024-08-26 11:12
challenge: nolibc
tags:
  - self managed heap
---

堆块结构：

```
    +---------+
    | size(32)|
    |---------|
    | fd      |
    |---------|
    | data ...|
    |---------|
    | unused  |
    |---------|
    | unused  |
    +---------+
```

可以很轻松地用加载文件的办法从 `/proc/self/maps` 获得地址信息，同时 load 和 save to file 的功能都存在可能的溢出，但是问题在于总的堆大小不超过 0x10000，文件操作前会先申请 0x7fff 的堆块，管理结构体也占用了 0x4010，看起来这个溢出没法用。估计要从其它地方找漏洞。

在 free 里面看到了一个非常可疑的逻辑：

```c
if ( work_ptr )
  {
    v0 = 0x10000 - (work_ptr - BSS_START);
    if ( v0 > *(_DWORD *)work_ptr )
      *(_DWORD *)work_ptr = v0 - 16;
  }
```

进一步研究进入这里的输入，同时实际堆空间是比设计中的小 0x10 的，如果把堆空间占满再删除前面的堆块就能进入上述释放后的整理分支：

[exp.py](exp.py)

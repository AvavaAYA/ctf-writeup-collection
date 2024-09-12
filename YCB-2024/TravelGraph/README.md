---
data: 2024-09-10 10:40
challenge: TravelGraph
tags:
  - Heapfengshui
---

漏洞很好找，delete 删除的不是列表元素 route 而是堆块头部。

因此可以利用不同大小的堆块拆分构造出 UAF，改了 transportation 域就可以无限大小堆溢出，打 house of apple + magic_gadget orw，本来以为不得不 setcontext，结果找到一篇非常详细的博客：

- [借助 svcudp_reply+26 把栈迁移到堆上就能打 ROP](https://bbs.kanxue.com/thread-272098.htm#msg_header_h3_29)

> [!note]
> 这道题的利用不够典型，板子可以参考后面的 [hard sandbox](../hard_sandbox)

[exp.py](./exp.py)

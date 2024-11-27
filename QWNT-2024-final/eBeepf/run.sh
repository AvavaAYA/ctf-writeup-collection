#!/bin/sh

qemu-system-x86_64 \
    -m 256M \
    -cpu qemu64,+smep,+smap \
    -kernel bzImage \
    -initrd rootfs.cpio \
    -monitor /dev/null \
    -append "console=ttyS0 kaslr quiet panic=1 kpti=on" \
    -drive file=/flag,if=virtio,format=raw,readonly=on \
    -drive file=player_exp,format=raw \
    -nographic

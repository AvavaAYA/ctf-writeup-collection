#!/bin/sh

qemu-system-x86_64 \
    -m 256M \
    -cpu qemu64,+smep,+smap \
    -kernel bzImage \
    -initrd rootfs.cpio \
    -monitor /dev/null \
    -append "console=ttyS0 kaslr quiet panic=1" \
    -netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
    -s \
    -nographic

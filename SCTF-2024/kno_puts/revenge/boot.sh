#!/usr/bin/env bash

qemu-system-x86_64 \
    -m 256M \
    -cpu qemu64,+smep,+smap \
    -kernel bzImage \
    -initrd rootfs.cpio \
    -monitor /dev/null \
    -append "console=ttyS0 kaslr quiet panic=1" \
    -drive file=exploit,format=raw \
    -s \
    -netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
    -nographic

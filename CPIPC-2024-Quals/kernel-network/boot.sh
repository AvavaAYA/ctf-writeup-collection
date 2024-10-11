#!/bin/sh

qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel ./bzImage \
    -initrd ./rootfs.img \
    -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 kaslr" \
    -smp cores=2,threads=1 \
    -cpu kvm64,+smep,+smap


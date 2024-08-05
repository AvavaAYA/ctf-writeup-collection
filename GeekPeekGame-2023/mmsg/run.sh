#!/bin/bash
qemu-system-x86_64 \
    -m 256M \
    -cpu host,+smep,+smap \
    -smp cores=1 \
    -kernel bzImage \
    -hda rootfs.img \
    -nographic \
    -monitor none \
    -snapshot \
    -enable-kvm \
    -append "console=ttyS0 root=/dev/sda rw rdinit=/sbin/init kaslr quiet oops=panic panic=1" \
    -no-reboot 

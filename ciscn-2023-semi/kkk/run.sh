#!/bin/sh
qemu-system-x86_64 \
    -m 256M \
    -cpu kvm64,+smep,+smap \
    -smp cores=1,threads=1 \
    -kernel bzImage \
    -initrd ./rootfs.cpio \
    -hda ./kkk.ko \
    -hdb ./flag \
    -nographic \
    -monitor /dev/null \
    -append "console=ttyS0 root=/dev/ram rdinit=/sbin/init kaslr pti=on quiet oops=panic panic=1" \
    -no-reboot

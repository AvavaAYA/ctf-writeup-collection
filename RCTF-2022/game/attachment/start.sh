#!/bin/bash
export KERNEL=.
export IMAGE=.
echo "start"
qemu-system-x86_64 \
    -m 128M \
    -kernel $KERNEL/bzImage \
    -nographic \
    -append 'console=ttyS0 loglevel=3 oops=panic panic=1 kaslr' \
    -initrd $IMAGE/rootfs.cpio \
    -monitor /dev/null \
    -smp cores=1,threads=1 \
    -cpu kvm64,smep,smap

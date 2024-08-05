#!/bin/bash

port=$1

qemu-system-x86_64 \
	-m 64M \
	-kernel ./bzImage \
	-initrd ./rootfs.cpio \
	-append "console=ttyS0 kaslr quiet" \
	-cpu kvm64,+smap,smep\
	-smp cores=1,threads=1 \
	-monitor /dev/null \
	-net nic \
	-net user,hostfwd=tcp:0.0.0.0:${port}-:22 \
	-nographic \
	-no-reboot

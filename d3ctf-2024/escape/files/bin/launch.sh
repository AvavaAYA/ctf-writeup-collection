#!/usr/bin/env bash

./qemu-system-x86_64 \
	-L ../pc-bios/ \
	-m 128M \
	-kernel vmlinuz \
	-initrd rootfs.img \
	-smp 1 \
	-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 nokaslr quiet" \
	-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
	-nographic \
	-monitor /dev/null \
	-device l0dev \
	-s

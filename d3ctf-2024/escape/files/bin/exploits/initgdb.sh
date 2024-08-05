#!/usr/bin/env bash

sudo -E pwndbg ./vmlinux.bin -ex "set architecture i386:x86-64" \
	-ex "target remote localhost:1234" \
	-ex "add-symbol-file ./rootfs/vuln.ko $1" \
	-ex "c"

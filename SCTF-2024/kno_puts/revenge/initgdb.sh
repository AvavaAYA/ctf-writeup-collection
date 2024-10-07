#!/usr/bin/env bash

sudo -E pwndbg ./vmlinux.bin -ex "set architecture i386:x86-64" \
    -ex "target remote host.orb.internal:1234" \
    -ex "add-symbol-file ./rootfs/test.ko $1" \
    -ex "b *($1 + 0x3fe)" \
    -ex "b *($1 + 0x637)" \
    -ex "b *($1 + 0xa2)" \
    -ex "c"

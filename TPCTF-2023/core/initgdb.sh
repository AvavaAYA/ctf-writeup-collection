#!/usr/bin/env fish

gdb ./vmlinux.bin \
	-ex "target remote localhost:1234" \
	-ex "add-symbol-file ./rootfs/baby.ko $argv" \
	-ex "set \$heap_var=$argv+0x2480" \
	-ex "b *add" \
	-ex "c"

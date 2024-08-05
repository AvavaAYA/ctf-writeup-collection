#!/usr/bin/sh

gdb-multiarch -ex "set architecture i386:x86_64" \
    -ex "target remote localhost:1234" \
    -ex "add-symbol-file ./d3kcache.ko $1" \
    -ex "b *($1 + 0x145)" \
    -ex "b *($1 + 0x1ea)" \
    -ex "b *($1 + 0x1dd)" \
    -ex "b *($1 + 0x26e)" \
    -ex "set \$chunklist = ($1 + 0x17D8 + 0xe00)" \
    -ex "set \$kcachelist = ($1 + 0x17D0)" \
    -ex "c"
    # write
    # read
    # release
    # allocate

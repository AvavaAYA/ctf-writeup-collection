#!/usr/bin/sh
gcc ass.c -ffunction-sections -fdata-sections -O0 -fno-asynchronous-unwind-tables --save-temps -fno-PIE -w -o ./ass
gdb ./ass -ex 'b *main' -ex 'r'

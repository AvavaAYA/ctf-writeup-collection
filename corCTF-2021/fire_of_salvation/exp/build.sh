#!/bin/sh

gcc ./exp.c -static -masm=intel -o ./exp
cp ./exp ../rootfs/exp/exp
cd ../rootfs
find . -print0 | cpio --null -ov --format=newc >../rootfs.cpio
cd ..
./run.sh

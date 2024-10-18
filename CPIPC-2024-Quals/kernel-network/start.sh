#!/bin/bash
echo "flag{testhudshah}" >_install/flag && cd ./_install && find . | cpio -o --format=newc >../rootfs.img && cd .. && sh boot.sh

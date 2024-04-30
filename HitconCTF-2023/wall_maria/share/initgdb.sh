#/usr/bin/env -c fish

pwndbg ./qemu-system-x86_64 -ex "target remote 127.0.0.1:6666"

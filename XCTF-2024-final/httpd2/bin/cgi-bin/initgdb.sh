#!/usr/bin/env bash

gdb ./exec.cgi -ex "target remote 127.0.0.1:1234" \
    -ex "b *main" \
    -ex "c" \
    -ex "b *genCookie" \
    -ex "c" \
    -ex "b *(&genCookie + 0xc5)" \
    -ex "c"

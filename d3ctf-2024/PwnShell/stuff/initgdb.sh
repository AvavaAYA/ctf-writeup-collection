#!/usr/bin/env bash

pwndbg -ex "target remote 127.0.0.1:1234" \
	-ex "add-symbol-file ./vuln.so 0x7ffff4609000" \
	-ex "b *(0x7ffff4609000 + 0x1210)" \
	-ex "disable" \
	-ex "tb *0x7ffff7fe5a43" \
	-ex "c" \
	-ex "ni" \
	-ex "tb *0x7ffff7326300" \
	-ex "si" \
	-ex "tb *0x555555647980" \
	-ex "c" \
	-ex "c" \
	-ex "tb *0x555555647b14" \
	-ex "c" \
	-ex "enable 1" \
	-ex "set \$list=(0x7ffff4609000+0x4160)" \
	-ex "b *(0x7ffff4609000 + 0x1410)" \
	-ex "b *(0x7ffff4609000 + 0x1520)" \
	-ex "b *(0x7ffff4609000 + 0x13d4)" \
	-ex "b *0x7ffff460a2c9" \
	-ex "c"

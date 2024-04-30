#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

import socket
import struct
import sys

ESXi_IP = "192.168.234.133"
SERVER_PORT = 1000

f = open(sys.argv[1], 'rb').read()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ESXi_IP, SERVER_PORT))
s.send(struct.pack("<I", len(f)))
for i in range(len(f) // 0x1000):
    s.sendall(f[i * 0x1000 : (i + 1) * 0x1000])
s.sendall(f[-(len(f) % 0x1000) :])
l = struct.unpack("<I", s.recv(4))[0]
data = b''

while len(data) < l:
    data += s.recv(l - len(data))
print(data)

s.close()

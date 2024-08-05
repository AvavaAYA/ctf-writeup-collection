#!/usr/bin/python3

import base64
import sys
from pwn import *

def main():
    p = remote("localhost", 1337)
    filename = sys.argv[1]
    with open(filename, "rb") as f:
        payload = base64.b64encode(f.read())
        p.sendline(payload)
    p.interactive()
        
if __name__ == "__main__":
    main()

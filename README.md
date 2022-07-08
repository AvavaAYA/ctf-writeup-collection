# ctf-writeup-collection

## Mostly pwn, keep updating.

### TO-DO

现在很多题中`free_hook`和`malloc_hook`都不能用了，最近打国内比赛遇到更多的是新版本下的利用，因此想拓展一下任意地址写成功后的利用思路:

 - [ ] House_of_Emma
 - [ ] House_of_kiwi
 - [ ] House_of_pig
 - [ ] House_of_banana

### Challenge-List
- [x] RoarCTF-2019
	- [x] realloc_magic
		 - glibc2.27 | realloc | IO
- [ ] ByteCTF-2021
	- [ ] bytezoom
	- [ ] byteCSMS
- [ ] HWS_online-2022
	- [ ] house_of_husk
	- [ ] peach
	- [ ] grape
- [ ] SUSCTF-2022
	- [ ] rain
	- [x] happyTree
		 - glibc2.27 | tcache
	- [ ] mujs
	- [ ] kqueue
	- [ ] kqueue_rev
- [ ] d3ctf-2022
	- [ ] d3fuse
	- [ ] d3bpf
	- [ ] d3guard
	- [ ] d3kheap
	- [ ] d3bpf-v2
	- [ ] smarCal
- [x] utCTF-2022
	- [x] bloat
		 - kernel
	- [x] automated-exp-gen
	- [x] smol
- [x] wolvseccon-2022
	- [x] Us3_th3_F0rc3
		 - house_of_force
- [ ] zer0pts-2022
	- [ ] 0av
	- [x] modern-rome
	- [ ] memsafed
	- [ ] sbxnote
	- [ ] redis-lite
- [ ] spaceHerosCTF-2022
	- [x] rule_of_2
	- [x] rings_of_saturn
	- [ ] fuzz_lightyear
- [x] HackPack-2022
	- [x] cerebrum-boggled
		 - brainfuck-jit | rop | rust
- [ ] \*CTF-2022 | (StarCTF-2022)
	- [x] examination
		 - glibc2.31 | heapfengshui
	- [ ] babynote
	- [ ] ping
	- [ ] babyarm
- [ ] MRCTF-2022
	- [ ] toy_bricks
	- [ ] zigzag
	- [ ] ezbash
	- [ ] dynamic
- [ ] PatriotCTF-2022
	- [ ] mcchttp
	- [x] Password-Manager
- [ ] DASCTF-MAY-2022
	- [ ] 山重水复
	- [ ] twists-and-turns
	- [ ] gift
- [ ] Dest0g3-520
	- [x] stack
	- [x] ezpwn
	- [x] ezkiwi
		- glibc2.31 | IO-attack | tcache
	- [x] ezuaf
		- glibc2.33 | tcache
	- [x] dest_love
		- string_fmt
	- [ ] emma
	- [ ] dest0g3_heap
- [ ] ciscn-2022-online
	- [x] login-nomal
	- [ ] satool
	- [x] newest_note
		- glibc2.34 | tcache & fastbin_doublefree
- [x] ciscn-2022-华东北
	- [x] duck
		- glibc2.34 | IO-attack
	- [x] bigduck
		- glibc2.33 | setcontext | orw
	- [x] blue
		- glibc2.31 | setcontext | chunk_overlap
- [ ] ACTF-2022
	- [ ] treepwn
	- [ ] kkk
	- [ ] myKVM
	- [ ] EasyKVM
	- [ ] master-of-DNS
	- [ ] 2048
- [ ] PCB-2022 | 鹏城杯-2022-online
	- [x] A_fruit
	- [ ] arm_prtoocol
	- [ ] fruitshop
	- [ ] signin_ROP

--------

More detailed wp can be found in my [homepage](https://avavaaya.github.io/).
# ctf-writeup-collection

> eastXueLian's reservoir of CTF puzzles.

I have pre-commit hooks for this readme:

- [update-readme](./helper/update_readme.py)
- [pre-commit](./helper/pre-commit)

## Challenges With Write-Up

| Source | Challenge | Keywords |
| :--: | :--: | :--: |
| [*CTF 2019](NULL) | [oob](./StarCTF-2019/pwn-OOB) | v8 |
| 👆 | [oob](./StarCTF-2019/pwn-OOB) | v8 |
| [GoogleCTF-2023](https://capturetheflag.withgoogle.com/challenges) | [ubf](./GoogleCTF-2023/ubf/) | int-overflow |
| 👆 | [](./GoogleCTF-2023/ubf) | coding: utf-8 -*-, (i), b"\x01") |
| 👆 | [](./GoogleCTF-2023/stroygen) |  |
| 👆 | [](./GoogleCTF-2023/gradebook) | coding: utf-8 -*-, 1), 0x60, ret_addr - addr), 0x2386 |
| 👆 | [stroygen](./GoogleCTF-2023/stroygen/) | Misc |
| 👆 | [gradebook](./GoogleCTF-2023/gradebook/) | TOCTOU |
| [GeekPeekGame-2023-preliminary](https://geekpeekgame.xctf.org.cn/) | [linkmap](./GeekPeekGame-2023/linkmap/) | stack-pivoting |
| [ciscn-2023-semi](https://arttnba3.cn/2023/07/14/CTF-0X09_CISCN_2023_HDBFQS/) | [minidb](./ciscn-2023-semi/minidb/) | heapfengshui |
| 👆 | [minidb](./ciscn-2023-semi/minidb) |  |
| [StarCTF-2023](https://adworld.xctf.org.cn/match/guide?event_hash=a37c4ee0-1808-11ee-ab28-000c29bc20bf) | [starvm](./StarCTF-2023/starvm/) | vm && tcache attack |
| 👆 | [fcalc](./StarCTF-2023/fcalc/) | IEEE 754 NaN && shellcode |
| 👆 | [drop](./StarCTF-2023/drop/) | rust |
| [SecurinetsCTFQuals2023](https://ctf.securinets.tn/) | [admin_service](./SecurinetsCTFQuals2023/admin_service/) | proc/self/maps |
| 👆 | [swix](./SecurinetsCTFQuals2023/swix) |  |
| 👆 | [execute_as_a_service](./SecurinetsCTFQuals2023/execute_as_a_service) |  |
| 👆 | [ret2libc](./SecurinetsCTFQuals2023/ret2libc/) | ld.so |
| [WACON 2023]() | [heaphp](./WACON-2023/heaphp/) | php |
| [WMCTF 2023](https://wmctf.wm-team.cn) | [blindless](./WMCTF-2023/blindless/) | house of blindless |
| [ACTF 2023]() | [blind](./actf-2023/blind) | BROP |
| 👆 | [master of orw](./actf-2023/master-of-orw) | seccomp-bypass, iouring |
| 👆 | [YoungManesCApe](./actf-2023/YoungManesCApe) | chroot escape |
| [京麒CTF - 2023]() | [solo-sudden death](./JQCTF-2023/solo-sudden_death) | solo |
| [D^3CTF 2024](https://race.d3ctf.cn/contest/1) | [PwnShell](d3ctf-2024/PwnShell/) | php, off-by-null |
| 👆 | [D3BabyEscape](d3ctf-2024/escape/) | qemu, escape |
| 👆 | [d3note](d3ctf/d3note/) | int-overflow |
| 👆 | [write_flag_where](d3ctf/write_flag_where/) | misc |
| 👆 | [d3lgfs](d3ctf/d3lgfs/) | windows, LPE |
| [北辰计划](https://eastxuelian.nebuu.la/bc-ctf-2024) | [pwn1](./Plan-BC-2024/pwn1) | small bof |
| 👆 | [pwn2](./Plan-BC-2024/pwn2) | strfmt, close stdout |
| 👆 | [pwn1](./Plan-BC-2024/pwn1) | small bof |
| 👆 | [pwn2](./Plan-BC-2024/pwn2) | strfmt, close stdout |
| [XCTF 2024 Final](./XCTF-2024-final) | [httpd2](./XCTF-2024-final/httpd2) | dlresolve, spary |
| 👆 | [httpd2](./XCTF-2024-final/httpd2) | dlresolve, spary |
| [DeadSec CTF 2024](https://deadsec.ctf.ae/) | [User management](./DeasSecCTF-2024/UserManagement) | strfmt |
| 👆 | [shadow](./DeasSecCTF-2024/shadow) | heap |
| 👆 | [gb](./DeasSecCTF-2024/gb) | VM pwn |
| 👆 | [Super CPP Calculator](./DeasSecCTF-2024/checkin) | IEEE 754 |
| 👆 | [User management](./DeasSecCTF-2024/UserManagement) | strfmt |
| 👆 | [gb](./DeasSecCTF-2024/gb) | VM pwn |
| 👆 | [shadow](./DeasSecCTF-2024/shadow) | heap |
| 👆 | [Super CPP Calculator](./DeasSecCTF-2024/checkin) | IEEE 754 |
| [TFC CTF 2024](https://ctf.thefewchosen.com) | [GUARD-THE-BYPASS](./TFCCTF-2024/GUARD-THE-BYPASS) | tls, canary bypass |
| 👆 | [VSPM](./TFCCTF-2024/VSPM) | double free |
| 👆 | [MCBACK2DABASICS](./TFCCTF-2024/MCBACK2DABASICS) | double free, scanf |
| 👆 | [GUARD-THE-BYPASS](./TFCCTF-2024/GUARD-THE-BYPASS) | tls, canary bypass |
| 👆 | [VSPM](./TFCCTF-2024/VSPM) | double free |
| 👆 | [MCBACK2DABASICS](./TFCCTF-2024/MCBACK2DABASICS) | double free, scanf |
| [GeekPeekGame-2023]() | [linkmap](./GeekPeekGame-2023/linkmap) |  |
| [HitconCTF-2023]() | [wall_maria](./HitconCTF-2023/wall_maria) |  |
| [PCB-2023]() | [atuo_coffee_sale_machine](./PCB-2023/atuo_coffee_sale_machine) |  |
| 👆 | [silent](./PCB-2023/silent) |  |
| [QWB-2022-online]() | [EasyEngine](./QWB-2022-online/EasyEngine) |  |
| [RCTF-2022]() | [diary](./RCTF-2022/diary) |  |
| [WMCTF-2023]() | [blindless](./WMCTF-2023/blindless) |  |
| [actf-2023]() | [](./actf-2023/YoungManesCApe) | 8], 8], 0x10, 8], 0x10], 0x18] |
| 👆 | [master-of-orw](./actf-2023/master-of-orw) |  |
| [d3ctf-2022]() | [d3fuse](./d3ctf-2022/d3fuse) |  |
| [d3ctf-2023]() | [d3kcache](./d3ctf-2023/d3kcache) |  |
| [idekCTF-2023]() | [](./idekCTF-2023/sprinter) | name: sprinter |
| [wangdingbei-2023]() | [half](./wangdingbei-2023/half) |  |

---

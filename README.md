# ctf-writeup-collection

> eastXueLian's reservoir of CTF puzzles.

I have pre-commit hooks for this readme:

- [update-readme](./helper/update_readme.py)
- [pre-commit](./helper/pre-commit)

## Challenges With Write-Up

| Source | Challenge | Keywords |
| :--: | :--: | :--: |
| [*CTF 2019](NULL) | [oob](./StarCTF-2019/pwn-OOB) | v8 |
| [GoogleCTF-2023](https://capturetheflag.withgoogle.com/challenges) | [ubf](./GoogleCTF-2023/ubf/) | int-overflow |
| 👆 | [stroygen](./GoogleCTF-2023/stroygen/) | Misc |
| 👆 | [gradebook](./GoogleCTF-2023/gradebook/) | TOCTOU |
| [GeekPeekGame-2023-preliminary](https://geekpeekgame.xctf.org.cn/) | [linkmap](./GeekPeekGame-2023/linkmap/) | stack-pivoting |
| [ciscn-2023-semi](https://arttnba3.cn/2023/07/14/CTF-0X09_CISCN_2023_HDBFQS/) | [minidb](./ciscn-2023-semi/minidb/) | heapfengshui |
| [StarCTF-2023](https://adworld.xctf.org.cn/match/guide?event_hash=a37c4ee0-1808-11ee-ab28-000c29bc20bf) | [starvm](./StarCTF-2023/starvm/) | vm, tcache attack |
| 👆 | [fcalc](./StarCTF-2023/fcalc/) | IEEE 754 NaN, shellcode |
| 👆 | [drop](./StarCTF-2023/drop/) | rust |
| [SecurinetsCTFQuals2023](https://ctf.securinets.tn/) | [admin_service](./SecurinetsCTFQuals2023/admin_service/) | proc/self/maps |
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
| [XCTF 2024 Final](./XCTF-2024-final) | [httpd2](./XCTF-2024-final/httpd2) | dlresolve, spary |
| [DeadSec CTF 2024](https://deadsec.ctf.ae/) | [User management](./DeasSecCTF-2024/UserManagement) | strfmt |
| 👆 | [gb](./DeasSecCTF-2024/gb) | VM pwn |
| 👆 | [shadow](./DeasSecCTF-2024/shadow) | heap |
| 👆 | [Super CPP Calculator](./DeasSecCTF-2024/checkin) | IEEE 754 |
| [TFC CTF 2024](https://ctf.thefewchosen.com) | [GUARD-THE-BYPASS](./TFCCTF-2024/GUARD-THE-BYPASS) | tls, canary bypass |
| 👆 | [VSPM](./TFCCTF-2024/VSPM) | double free |
| 👆 | [MCBACK2DABASICS](./TFCCTF-2024/MCBACK2DABASICS) | double free, scanf |
| [LIT CTF 2024](https://lit.lhsmathcs.org/ctf/challenges) | [How to Raise a Boring Vuln Flat](./LITCTF-2024/bflat) | strfmt outof stack, burp |
| 👆 | [w4dup 2de](./LITCTF-2024/w4dup) | ret2dlresolve, dup |
| 👆 | [recurse](./LITCTF-2024/recurse) | c attribute |
| 👆 | [iloveseccomp](./LITCTF-2024/iloveseccomp) | side channel, exit value |
| 👆 | [How to Raise a Boring Vuln](./LITCTF-2024/boring) | scanf, qsort |
| [巅峰极客 2024](https://endbm.ichunqiu.com/2024dfjk) | [easyblind](./dfjk-2024/easyblind) | nightmare, linkmap, ld.so |
| [SEKAI CTF 2024](https://ctf.sekai.team/) | [nolibc](./SekaiCTF-2024/nolibc) | self managed heap |
| 👆 | [speedpwn](./SekaiCTF-2024/speedpwn) | fsop, scanf |

---


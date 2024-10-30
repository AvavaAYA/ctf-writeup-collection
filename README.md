# ctf-writeup-collection

> eastXueLian's reservoir of CTF puzzles.

I have pre-commit hooks for this readme:

- [update-readme](./helper/update_readme.py)
- [pre-commit](./helper/pre-commit)

## Challenges With Write-Up

| Source | Challenge | Keywords |
| -- | -- | -- |
| [*CTF 2019](NULL) | [oob](./StarCTF-2019/pwn-OOB) | v8 |
| [HackPack CTF 2022](https://ctf2022.hackpack.club/) | [Cerebrum Boggled](./HackPack-2022/cerebrum-boggled) | brainfuck, jit |
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
| [ACTF 2023]() | [blind](./actf-2023/blind) | BROP with PIE |
| 👆 | [master of orw](./actf-2023/master-of-orw) | seccomp-bypass, iouring |
| 👆 | [YoungManesCApe](./actf-2023/YoungManesCApe) | chroot escape |
| [京麒CTF - 2023](./JQCTF-2023/) | [solo-sudden death](./JQCTF-2023/solo-sudden_death) | solo |
| 👆 | [Re: 从一开始的 orw 生活](./JQCTF-2023/from_1_to_N) | iouring |
| [b01lers CTF 2024](https://ctf.b01lers.com/home) | [mixtpeailbc](./b01lersCTF-2024/mixtpeailbc) | VM pwn |
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
| [羊城杯 2024](https://2024ycb.dasctf.com/) | [TravelGraph](./YCB-2024/TravelGraph) | heapfengshui |
| 👆 | [pstack](./YCB-2024/pstack) | stack pivoting |
| 👆 | [logger](./YCB-2024/logger) | CHOP, try-catch |
| 👆 | [httpd](./YCB-2024/httpd) | misc, URLencode |
| 👆 | [hard sandbox](./YCB-2024/hard_sandbox) | ptrace, seccomp-bypass |
| [WMCTF 2024](https://wmctf.wm-team.cn/) | [evm](./WMCTF-2024/evm) | vm pwn |
| 👆 | [magicpp](./WMCTF-2024/magicpp) | cpp vector |
| [SCTF 2024](https://ctftime.org/event/2483/) | [kno_puts](./SCTF-2024/kno_puts) | kernel, userfaultfd race |
| [BRICS+ CTF 2024](https://brics-ctf.com/) | [chains](./BRICSCTF-2024/chains) | UAF |
| 👆 | [physler](./BRICSCTF-2024/physler) | kernel |
| 👆 | [gollum](./BRICSCTF-2024/gollum) | go |
| [华为杯研赛 2024](https://cpipc.acge.org.cn/cw/hp/2c90800c8093eef401809d33b36f0652) | [cancanneed_new](./CPIPC-2024-Quals/cancanneed_new) | IO |
| 👆 | [stack_and_heap](./CPIPC-2024-Quals/stack_and_heap) | double free |
| 👆 | [mips_fmt](./CPIPC-2024-Quals/mips_fmt) | mips32, strfmt |
| 👆 | [kernel-network](./CPIPC-2024-Quals/kernel-network) | kernel, UAF |
| [安网杯 2024](https://t.me/rin_notebook/1408?comment=1959) | [pwn1](./AWB-2024/pwn1) | VM pwn |
| [TCP1P CTF 2024](https://github.com/TCP1P/TCP1P-CTF-2024-Challenges-Public) | [Baby CFHP](./TCP1PCTF-2024/baby_cfhp) | IO |
| [网鼎杯 2024 青龙组线上](https://www.wangdingcup.com/) | [pwn-02](./wangdingbei-qual-2024/pwn02) | stack pivoting |

---


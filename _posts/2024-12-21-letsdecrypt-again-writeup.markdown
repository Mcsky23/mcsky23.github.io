_---
layout: post
title:  "Cryptohack - Let's Decrypt Again"
date:   2024-12-21 11:00:00 +0000
categories: writeups
description: "Using discrete logarithms to forge signatures by crafting custom decryption exponents."
---

# Cryptohack - Let's Decrypt Again

**Note**: I am in no way a math expert so feel free to correct me if I make any theoretical mistakes in this post. This writeup has the role of documenting my cryptography learning process. Maybe you can learn something from it too.

## Overview

So what is this challenge about? Well, we are given an implementation of a signature scheme based on RSA. The server basically signs a message using it's private key and checks if the message we send matches the signature. Let's take a closer look!

## "Reversing"

Firstly, we notice that the server uses RSA parameters that we, obviously, don't have access to: `from params import N, E, D`. Then it signs a "server message". 

**Recall** that RSA signing is done by encrypting the message with the private key instead of the public key. This means `signature = pow(server_message, D, N)`.

```python
MSG = b'We are hyperreality and Jack and we own CryptoHack.org'
DIGEST = emsa_pkcs1_v15.encode(MSG, BIT_LENGTH // 8)
SIGNATURE = pow(bytes_to_long(DIGEST), D, N)
```

Notice that it's using the `emsa_pkcs1_v15` padding and hashing scheme. This prevents us from exploiting the `homomorphic` property of RSA.

**Next**, let's have a look at how we can interact with this server:
- we can request the server's public key and signature of the server message
```python
elif your_input['option'] == 'get_signature':
    return {
        "N": hex(N),
        "E": hex(E),
        "signature": hex(SIGNATURE)
    }
```
- we can set a public key that will be used to verify the signatures. There is a catch however. A random, unguessable, suffix will be generated that will need to be appended to the message we try to verify. 
    - **Why is this measure implemented?**
    If there were no random suffix, we could simply set `e = 1` and `n = server_signature - custom_msg_digest`. See the problem? $server\_signature^{1} \equiv custom\_msg\_digest \mod N$. 
    This would allow us to forge any signature we want. This is in fact the idea behind `Let's Decrypt`, also from `Cryptohack`.

- last, but not least, we can "claim" a message, that is, we can provide a message, a public exponent and an index(will talk about this later) and the server will check if: 
    - $hash(msg) = signature^{e} \mod N$. In other words, it will check if our message's signature is the same as the server's signature.

**But what is the goal?** Earlier, I said that we can provide an index when claiming a message. When the challenge starts, the server 3 byte strings of length `len(FLAG)` in the following way:

$shares[0] = random\_bytes(len(FLAG))$

$shares[1] = random\_bytes(len(FLAG))$

$shares[2] = shares[0] \oplus shares[1] \oplus FLAG$

Recovering all 3 shares will allow us to recover the flag. The server leaks these shares if we manage to forge signatures for messages that match the following patterns:
```python
PATTERNS = [
    re.compile(r"^This is a test(.*)for a fake signature.$").match,
    re.compile(r"^My name is ([a-zA-Z\s]+) and I own CryptoHack.org$").match,
    btc_check
]
```

`btc_check` checks if the message follows the following format: "Please send all my money to ADDR", where `ADDR` is a valid `p2sh` bitcoin address. You can take a look at the `btc_check` function in the source code to confirm this.

## Forging signatures

Before we get to forging signatures, we need to have something to forge, let's pick the 3 messages:

```python
msg1 = b"This is a test message for a fake signature."
msg2 = b"My name is mcsky and I own CryptoHack.org"
msg3 = b"Please send all my money to 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
```

Cool, now let's get to forging.

Firstly, let's make it clear what we want to achieve. We control the RSA **modulus**, but we can only pick it once. We also control the **public exponent** for every message we claim. So let's rephrase the problem.

<!-- $Given\ an\ integer\ S,\ find\ a\ modulus\ N\ such\ that\ for\ the\ messages \{m{_1}, m{_2}, m{_3}\} and public exponents \{e{_1}, e{_2}, e{_3}\}, we have: $ -->

$\text{Given an integer }S,\ \text{find a modulus }N\ \text{such that for the messages } \{m{_1}, m{_2}, m{_3}, ... m{_n}\}\\\ \text{we can compute in polynomial time the public exponents } \{e{_1}, e{_2}, e{_3}, ... e{_n}\}\ \text{such that:}\\ S^{e{_i}} \equiv m{_i} \mod N$.

Notice that:
$e{_i} = log_{S}(m{_i})\ mod\ N$

This is actually the `discrete logarithm problem`. **Recall** that the discrete logarithm problem is the following: given $g, h, p$, find $x$ such that $g^{x} \equiv h\ mod\ p$. It's basically `a logarithm in a finite field`.

So, the plan is to find a number $N$ such that we can easily compute any discrete logarithm with the base $S$. The discrete logarithm problem is known to be a hard problem in general and there **isn't** a known polynomial time algorithm to solve it. However, there are some cases where it can be solved in feasible time. For starters, we can take a look at the [Algorithms chapter on the Wikipedia page of DLP](https://en.wikipedia.org/wiki/Discrete_logarithm#Algorithms). 

### Pohlig-Hellman algorithm

More specifically, we can take a look at the `Pohlig-Hellman` algorithm. It attempts to solve the `DLP`(discrete logarithm problem) in `a finite abelian group whose order is a smooth number`.

**Recall**: 
- An n-smooth number is a number that has only prime factors less than or equal to n.
- The order of a group is the number of elements in the group.

In our case, the `finite abelian group` is actually the `multiplicative group of integers modulo N`. The order of this group is $\phi(N)$, where $\phi$ is Euler's totient function.

`Pohlig-Hellman's` algorithm works by breaking the `DLP` into subgroups of prime order. It solves the `DLP` in each subgroup and then combines the results using the `Chinese Remainder Theorem`. In fact, if a group has order $p$, where $p$ is prime, it's order is $p-1$. If $p-1$ is sufficiently smooth, that is, it has small prime factors, then the `DLP` can be solved in efficient time. You can read more [here](https://www.hyperelliptic.org/tanja/teaching/crypto20/pohlig-hellman.pdf).


### Solving the challenge

Taking everything into consideration, we _almost_ have a solution. There are 2 obstacles left:
- this check: `if isPrime(pubkey): return {"error": "Everyone knows RSA keys are not primes..."}`. We can't have a prime modulus. To circumvent this, we can simply choose n to be $p^{2}$, where $p$ is a prime and $p-1$ is sufficiently smooth. Thus, the order of the group will be $p(p-1)$, which is sufficiently smooth if divided into subgroups.
- even if we manage to choose an $N$ that makes solving the `DLP` feasible, we still need to make sure that the base we are trying to solve for is a generator of the group. In other words, $signature$ is a **primitive root** modulo $N$. If it's not, the `DLP` has no solution.

### Implementation

Generate a prime $p$ such that $p-1$ is smooth enough:

```python
def generate_smooth_prime(min_bound, signature=SIGNATURE):
    """
    generates a number p that is prime and p-1 is smooth
    we also need to make sure that the signature is a primitive root
    """
    r = 2
    p = 1
    while True:
        p *= r
        r = next_prime(r)
        if is_prime(p + 1) and p + 1 > min_bound:
            if not Zmod(p + 1)(signature).is_primitive_root():
                continue
            return p + 1
```

Define multiplicative group and compute the public exponents:

```python
K = Zmod(n)
print("signature is generator for Zmod(n):", K(SIGNATURE).is_primitive_root())
shares = []
for (i, msg_digest) in enumerate(msgs_digest):
    dlog = K(msg_digest).log(K(SIGNATURE))
    print(f"dlog for {msg_digest = } is {dlog = }")
    claim_res = claim(msgs[i], dlog, i)
    print(f"{claim_res = }")
    shares.append(bytes.fromhex(claim_res['secret']))
    print(f"Claimed {i = }")
```

Here is the full exploit script written in `SageMath`:

```python
from curses.ascii import SI
from sage.all import *
from Pwn4Sage import remote
from pkcs1 import emsa_pkcs1_v15
import json

r = remote('socket.cryptohack.org', 13394)

r.recvuntil(b"Just do it multiple times to make sure...\n")

r.sendline(b'{"option": "get_signature"}')
aux = json.loads(r.recvline().strip())
N = int(aux['N'], 16)
E = int(aux['E'], 16)
SIGNATURE = int(aux['signature'], 16)

print(f"{N = }")
print(f"{E = }")
print(f"{SIGNATURE = }")

BIT_LENGTH = 768

msg1 = b"This is a test message for a fake signature."
msg2 = b"My name is mcsky and I own CryptoHack.org"
msg3 = b"Please send all my money to 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
msgs = [msg1, msg2, msg3]

def set_pubkey(n):
    r.sendline(json.dumps({"option": "set_pubkey", "pubkey": hex(n)[2:]}).encode())
    aux = json.loads(r.recvline().strip())
    return aux['suffix']

def claim(msg, e, index):
    dat = {"option": "claim", "msg": msg.decode(), "e": hex(e), "index": index}
    dat = str(dat).replace("'", '"').encode()
    print(dat)
    r.sendline(dat)
    aux = json.loads(r.recvline().strip())
    return aux

def generate_smooth_prime(min_bound=2**32, signature=SIGNATURE):
    """
    generates a number p that is prime and p-1 is smooth
    we also need to make sure that the signature is a primitive root
    """
    r = 2
    p = 1
    while True:
        p *= r
        r = next_prime(r)
        if is_prime(p + 1) and p + 1 > min_bound:
            if not Zmod(p + 1)(signature).is_primitive_root():
                continue
            return p + 1
        
def xor(a, b):
    assert len(a) == len(b)
    return bytes(x ^^ y for x, y in zip(a, b))
        
p = generate_smooth_prime(min_bound=N, signature=SIGNATURE)
print("Generated smooth prime:", p)
n = p**2

suffix = set_pubkey(n)

msgs = [msg + suffix.encode() for msg in msgs]
msgs_digest = [emsa_pkcs1_v15.encode(msg, BIT_LENGTH // 8) for msg in msgs]
msgs_digest = [int.from_bytes(msg_digest, 'big') for msg_digest in msgs_digest]

K = Zmod(n)
print("signature is generator for Zmod(n):", K(SIGNATURE).is_primitive_root())

shares = []

for (i, msg_digest) in enumerate(msgs_digest):
    dlog = K(msg_digest).log(K(SIGNATURE))
    print(f"dlog for {msg_digest = } is {dlog = }")
    claim_res = claim(msgs[i], dlog, i)
    print(f"{claim_res = }")
    shares.append(bytes.fromhex(claim_res['secret']))
    print(f"Claimed {i = }")

# xor the shares to get the flag
flag = shares[0]
for share in shares[1:]:
    flag = xor(flag, share)

print("Flag:", flag)
r.close()
```

### Conclusion

This was a fun challenge and a neat opportunity to research about `Pohlig-Hellman` and the `Discrete Logarithm Problem`. You can dm me on discord @mcsky23 if you have any questions or think that I made a mistake in this writeup. Good luck!

### Exercice for the reader

How would you defend this scheme against the attack I just described?
_
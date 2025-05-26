![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>Phoenix Zero Trust</font>

​	2<sup>th</sup> May 2025

​	Prepared By: `rasti`

​	Challenge Author(s): `magicfrank`

​	Difficulty: <font color='green'>Easy</font>



# Synopsis

- This challenge revolves around bypassing a Schnorr-based authentication scheme. By recovering the internal state of the Mersenne Twister PRNG used to generate challenges, it becomes possible to forge a valid proof without knowing the secret key.

## Description

- Within Volnaya's labyrinth of secrets lies an unseen gate, guarded by an invisible sentinel. Task Force Phoenix must wield trust without revealing their own, negotiating passage through cryptographic darkness where identities vanish and only the truth remains.



## Skills Required

- Knowledge of Schnorr identification schemes
- Understanding of Mersenne Twister and PRNG state recovery

## Skills Learned

- Constructing zero-knowledge proof simulators
- Reversing PRNG output via output parsing and state recovery

# Enumeration

## Analyzing the source code

In this challenge we are given a single file:
- main.rs: A Rust implementation of a Schnorr zero-knowledge login protocol using standard parameters from RFC 7919.

The server maintains a hardcoded user overwatch with a known public key. Authentication follows the Schnorr protocol:
1. The user submits a commitment u = g^r mod p.
2. The server issues a random challenge c.
3. The user replies with z = r + c·x mod q.
4. The server checks that g^z ≡ u·h^c mod p.

The critical component is that the challenge c is generated using a Mersenne Twister (rand_mt), which is deterministic and state-recoverable.

# Solution

## Finding the vulnerability

While the Schnorr protocol is sound (an attacker can't pass verification without knowing the secret key), in the challenge we can exploit the use of Mersenne Twister as the random number generator.

The protocol is perfect zero knowledge, which means that for any valid challenge c, a simulator can craft a convincing (u, z) pair without ever knowing the witness (key for the dlog):

1. Choose random c and z.
2. Compute u = g^z / h^c mod p.

Here the simulator just crafter a valid transcript that is exactly indistinguishable from a real one. The only difference is that the simulator can 'cheat' with choosing c, while in the protocol is the server that chooses it.

Here, if we can predict the next challenge before sending the commitment, we can simulate a valid proof without knowing the secret key.

## Exploitation

### Attacking Mersenne Twister 
The random challenge $c$ is generated using a Mersenne Twister
```rs
use rand_mt::Mt as CSRNG;
[...]
fn schnorr_challenge(p: &BigUint, rng: &mut CSRNG) -> BigUint {
    rng.gen_biguint_range(&BigUint::one(), p)
}
```
For the construction of the MT, if we manage to extract 624 consecutive 32bits output, then we can recover the seed and predict every future (and past) number.
In this case we don't see 32bits output, but we see the output of `rand_range(0,p)`.

Luckily, `p` is a 2048bits prime (nice multiple of 32), and for how the MT works, to generate a N-bit number, it samples 32bits at a time untill it fills all the bit. In this case, it generates 64times `rng.get_rand_bits(32)` and then concatenates the result to get the final number.

This can be seen also experimenting a bit even with the python implementation of the MT:
```python
>>> random.seed(1337)
>>> hex(random.randrange(1,p))
'0x9ac68d26ea43fe43ebf96c57b0c751a5ade42791505078bada1298c4cbb452ae2bd4e7abf522dfdc3f12cc0c75ffbff51e5876bf982e524e5a695365d51f25e60490392aa9eb72624f93de30ccd1118fbccfb637cd367ad167433a8667518339e369ab3d591d3569ab0a0d83b2ff51348161701f10ba53d8e66eb1186613c33da29c4db3d20833556cecc2581bfa530d5d685155e98cd7d9dd23f7b6a801cf8bc2f40b3034775758b2767375fe03e76f643cb56d4ec10fc6fee29f53ebf644bb5c1ed35fca2410fda28718e5623a7a755531ae6dd30a286ec6737b8b2a6a7b5fbb5d75b895f628f2922badb05da83cffb5bab1cd888417a5ecefe37b9e250d04'
>>> random.seed(1337)
>>> hex(random.getrandbits(32))
'0x9e250d03'
>>> hex(random.getrandbits(32))
'0xecefe37b'
>>> hex(random.getrandbits(32))
'0x888417a5'
...
```

We can see that the output of the first `getrandbits` is the lowest 32bits of the final number (minus 1, as the range is [1,p]), the second is the next 32bits, and so on.

Parsing those 64 numbers we can just submit them to RandCrack and predict the future challenge $c$.


### Exploit
First connect with `pwntools`
```py
from pwn import process, remote
from randcrack import RandCrack
import random

r = remote('0.0.0.0', 1337)
p = 0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF
```


Now we have to recover 624 consecutive 32-bits output from the server. We can do this by sending 10 times the login request, and then parsing the output of the challenge.
```py
outs = []
for _ in range(10):
    r.sendline(b'2')
    r.sendline(b'overwatch')
    r.sendline(b'1')
    r.sendline(b'1')
    r.recvuntil(b'Challenge c: ')
    c = int(r.recvline().strip().decode())
    c -= 1
    for _ in range(64):
        outs.append(c & 0xffffffff)
        c >>= 32
```

Using RandCrack (or any other tool) now we can recover the internal state of the Mersenne Twister. 
```py
rc = RandCrack()
for i in range(624):
    rc.submit(outs[i])
for i in range(624, len(outs)): 
    rc.predict_getrandbits(32) # syncronize the state to the server one
```

And at this point we can predict the next challenge and create a valid proof running the simulator
```py
# predict next chall
nextc = rc.predict_randint(1,p-1)

r.sendline(b'3')
r.recvuntil(b'overwatch: ')
pubkey = int(r.recvline().strip().decode())

# now knowing the chall i can pass the login
c = nextc
z = random.randint(1, (p-1)//2 - 1)
# return pow(g, z, p) == u * pow(h, c, p) % p
g = 2
u = pow(g, z, p) * pow(pow(pubkey, c, p),-1,p) % p
r.sendline(b'2')
r.sendline(b'overwatch')
r.sendline(str(u).encode())
r.sendline(str(z).encode())
r.interactive()
```
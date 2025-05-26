![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>Hidden Handshake</font>

​	2<sup>th</sup> May 2025

​	Prepared By: `rasti`

​	Challenge Author(s): `magicfrank`

​	Difficulty: <font color='green'>Easy</font>


# Synopsis

- This challenge exploits a vulnerability in AES-CTR mode where the key and nonce are reused. By controlling the nonce and partially predicting the plaintext, you can recover a partial keystream.

## Description

- Amidst the static hum of Volnaya's encrypted comms, Task Force Phoenix detects a subtle, silent handshake—a fleeting, ghostly link hidden beneath layers of noise. Your objective: capture, decode, and neutralize this quiet whisper before it escalates into a deafening roar that plunges nations into chaos.



## Skills Required

- Understanding of AES in CTR mode and its vulnerabilities
- Familiarity with keystream recovery through chosen plaintext attacks

## Skills Learned

- Leveraging partial plaintext knowledge for full message recovery

# Enumeration

## Analyzing the source code

In this challenge we are given a single file:
- server.py: The source code of the running service, which encrypts and prints a message containing the flag.

The script uses AES in CTR mode to encrypt a message built from a static `server_secret` and a user-controlled `Agent Codename`. The encryption key is derived via SHA-256 from the concatenation of `server_secret` and a user-provided 8-character `pass2`, which is also used as the CTR nonce.

# Solution

## Finding the vulnerability

One could think to just guess the secret key, but to do that we would need to brute-force the `server_secret`. 
This is not feasible as to brute-force the 8-character password we would need to try $37^8$ combinations, which is around $2^{42}$.

Looking carefully at the code we notice that `pass2` is used not only for the key-derivation, but also as the nonce. This means that we can send multiple times the same `pass2` and AES-CTR will reuse the same keystream.

As the encryption now becomes a simple XOR with a constant unknown KEYSTREAM, if we know the plaintext we can extract the keystream and decrypt anything.

Unfortunately we don't know the full plaintext, but we can control the `user` input. 

Still, we can send a very long username to extract a pretty big fraction of the keystream, and then send a very small username so that the flag encryption part will use the recovered keystream.

## Exploitation

First we connect to the challenge with pwntools
```python
from pwn import emote, xor

r = remote('0.0.0.0', 1337)
```

Then we trigger an encryption with a long username (`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`), and with the nonce set to `CONSTANT`.
```py
my_nonce = b'CONSTANT'
r.sendline(my_nonce)
r.sendline(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
r.recvuntil(b'Encrypted transmission: ')
ciphertext = bytes.fromhex(r.recvline().strip().decode())
```

Now we can extract the keystream by XORing the ciphertext with the plaintext. Here we don't know the full plaintext, but we know that the first part is `Agent ..., your clearance for Operation Blackout is: `, so we can just XOR the ciphertext with this known part, recovering the first ~120bytes of the keystream.
```py
plaintext = b"Agent aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, your clearance for Operation Blackout is: "
keystream = xor(ciphertext, plaintext)
```

At this point we trigger a second encryption with a very short username (`a`), and the same nonce, so that the flag will be encrypted with the bytes of the keysream we recovered before.
```py
r.sendline(my_nonce)
r.sendline(b'a')
r.recvuntil(b'Encrypted transmission: ')

ciphertext2 = bytes.fromhex(r.recvline().strip().decode())
print(xor(ciphertext2, keystream[:len(ciphertext2)]))
```
If we were to send instead another long username, then the flag part would be XORed with the unknown part of the keystream, and we would not be able to recover it.


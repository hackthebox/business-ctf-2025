![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>Transcoded</font>

​	5<sup>th</sup> May 2025

​	Prepared By: `rasti`

​	Challenge Author(s): `rasti`

​	Difficulty: <font color=lightgreen>Very Easy</font>

​	Classification: Official

# Synopsis

- `Transcoded` is a very easy challenge which teaches players about custom encoding schemes. The players will have to find out that the letter mapping remains static throughout the entire connection so they can send messages until they obtain the custom secret alphabet so that they can reverse the mapping of the encoded flag and finally decode it.

## Description

- While monitoring low-level signal traffic from Volnaya's outer provinces, Phoenix intercepted strange bursts of encoded chatter. Analysts believe it's training data for new field agents-simple, redundant, yet oddly resistant to conventional parsing. Overwatch suspects it's an onboarding ritual cloaked in noise.



## Skills Required

- Familiar with Base64 encoding

## Skills Learned

- Learn about custom encoding schemes.

# Enumeration

In this challenge we are provided with a single file:

- `server.py` : The main script that is executed when we connect to the docker instance

## Analyzing the source code

If we look at the `source.py` script we can see that the flow is straight forward. Let us start with main.

```python
def get_option():
    print('1. Try custom transcoder')
    print('2. Get transcoded secret')
    print('3. Exit')
    return input('> ')

FLAG = open('flag.txt', 'rb').read().strip()

if __name__ == '__main__':
    while True:
        option = get_option()
        if option == '1':
            msg = input('Enter the message you want to transcode :: ').encode()
            print(b64e(msg).decode())
        elif option == '2':
            print(b64e(FLAG).decode())
        elif option == '3':
            print('[!] See you.')
            break
        else:
            print('[-] Unknown option.')
```

We have three options:

1. The server encodes our own message and outputs it.
2. The server encodes the challenge flag and outputs it.
3. Exit the application

Let us see what `b64e` looks like:

```python
from base64 import b64encode
from random import shuffle
import string

STD_ALPHABET    = list(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
CUSTOM_ALPHABET = list((string.digits + string.ascii_letters[:-2] + string.punctuation[8:12]).encode())
shuffle(CUSTOM_ALPHABET)

def b64e(m: bytes) -> bytes:
    nm = b64encode(m).strip(b'=')
    return bytes(CUSTOM_ALPHABET[STD_ALPHABET.index(nm[i])] for i in range(len(nm)))
```

We can see the standard alphabet used for Base64 and then the custom alphabet `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX)*+,`. However, the custom alphabet is shuffled and the resulting alphabet remains unknown to us. The function `b64e` base64-encodes the input `m` and replaces all the characters from the standard alphabet with those of the shuffled custom alphabet based on each character. For example, the $i$-th character of the standard alphabet, would be replaced with the $i$-th character of the custom alphabet. The task is to retrieve the shuffled alphabet and manage to decode the flag.

# Solution

We observe that the custom alphabet is shuffled only once and is used for any message we send for encoding. Take the following example:

```python
>>> import base64
>>> base64.b64encode(b'HackTheBox').strip(b'=')
b'SGFja1RoZUJveA'
```

Sending `HackTheBox` to the server, we get:

```
B4sp61jgvL0,IK
```

This means that the letter `S` was replaced by `B`, the letter `G` by `4` and so on. However, the letter mapping is static throughout our connection. Thus, any time the letter `S` appears in the classic Base64 encoding of the message, it will always be mapped to `B`. Given a single message, we learned what 14 out of 64 letters are mapped to. We can keep sending messages until we have a mapping for all 64 letters and then we will be able to decode the flag.

```python
import string

io = remote('localhost', 1337)

def get_encoded_message(m):
  	io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b' :: ', m.encode())
    enc_msg = io.recvline().strip()
    return enc_msg
```

# Exploitation

Let us first write a function that sends a message to the server and receives the encoded message.

```python
from pwn import remote

io = remote('localhost', 1337)

def get_encoded_message(m):
  	io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b' :: ', m.encode())
    enc_msg = io.recvline().strip()
    return enc_msg
```

For the mapping, we will use a dictionary with the keys being the characters of the standard alphabet and the values, the characters of the shuffled custom alphabet.

```python
d = {}
while True:
    msg = ''.join(random.choices(alph, k=50))
    real_b64e_msg = b64encode(msg.encode()).strip(b'=')
    server_b64e_msg = get_encoded_message(msg)
    for real, server in zip(real_b64e_msg, server_b64e_msg):
        if real not in d:
            d[real] = server
    if len(d.keys()) == len(STD_ALPHABET):
        break
```

Last but not least, we will write a function that receives an encoded message and returns the decoded message.

```python
CUSTOM_ALPHABET = []
for a in STD_ALPHABET:
    CUSTOM_ALPHABET.append(d[a])

def b64d(m: bytes) -> bytes:
    nm = bytes(STD_ALPHABET[CUSTOM_ALPHABET.index(m[i])] for i in range(len(m)))
    try:
        return b64decode(nm + b'=')
    except:
        return b64decode(nm + b'==')
```



## Getting the flag

A final summary of all that was said above:

1. Observe that the letter mapping remains static throught the entire connection.
2. This enables us to send messages until we know what all 64 characters are mapped to.
3. Knowing the custom alphabet, we can reverse the mapping and decode the encoded flag.

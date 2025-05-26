from pwn import remote
import string, random, sys
from base64 import b64encode, b64decode

HOST, PORT = sys.argv[1].split(':') if len(sys.argv) > 1 else ('localhost', 1337)

io = remote(HOST, PORT)

STD_ALPHABET = list(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
alph = list(string.printable[:-6])

io.sendlineafter(b'> ', b'2')
enc_flag = io.recvline().strip()

d = {}
while True:
    msg = ''.join(random.choices(alph, k=50))
    real_b64e_msg = b64encode(msg.encode()).strip(b'=')
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b' :: ', msg.encode())
    server_b64e_msg = io.recvline().strip()
    for real, server in zip(real_b64e_msg, server_b64e_msg):
        if real not in d:
            d[real] = server
    if len(d.keys()) == len(STD_ALPHABET):
        break

CUSTOM_ALPHABET = []
for a in STD_ALPHABET:
    CUSTOM_ALPHABET.append(d[a])

def b64d(m: bytes) -> bytes:
    nm = bytes(STD_ALPHABET[CUSTOM_ALPHABET.index(m[i])] for i in range(len(m)))
    try:
        return b64decode(nm + b'=')
    except:
        return b64decode(nm + b'==')

print(b64d(enc_flag))
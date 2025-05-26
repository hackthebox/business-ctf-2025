from pwn import process, remote, xor
import sys

if len(sys.argv) > 1:
    host, port = sys.argv[1].split(':')
    io = remote(host, port)
else:
    io = process(['python3', '../challenge/server.py'])

pass2 = b'A' * 8
username = b'X' * 1000

known = f'Agent {username}, your clearance for Operation Blackout is: '.encode()

io.sendlineafter(b'key: ', pass2)
io.sendlineafter(b'Codename: ', username)
io.recvuntil(b'transmission: ')
ct1 = bytes.fromhex(io.recvline().strip().decode())

username = b'X' * 5
io.sendlineafter(b'key: ', pass2)
io.sendlineafter(b'Codename: ', username)
io.recvuntil(b'transmission: ')
ct2 = bytes.fromhex(io.recvline().strip().decode())

pt = xor(known, ct1, ct2)

import re
print(re.search(rb'(HTB{.*})\. It is', pt).groups(1)[0].decode())
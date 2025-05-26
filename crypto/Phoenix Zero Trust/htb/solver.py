from pwn import process, remote
from randcrack import RandCrack
import random, sys

HOST, PORT = sys.argv[1].split(':') if len(sys.argv) > 1 else ('localhost', 1337)

r = remote(HOST, PORT)

p = 0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF

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

rc = RandCrack()
for i in range(624):
    rc.submit(outs[i])
for i in range(624, len(outs)):
    rc.predict_getrandbits(32) # discard the last one

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
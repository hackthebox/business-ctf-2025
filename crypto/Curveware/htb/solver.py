from sage.all import *
import os, glob

REPO_PATH = '/Users/aristomenistressos/Downloads/crypto_curveware/business-ctf-2025-dev'

LEAKS = []
R = []
S = []
for root, dirs, files in os.walk(REPO_PATH):
    for f in files:
        sig = open(f'{root}/{f}', 'rb').read()[:0x40]
        R.append(int(sig[0x00:0x20].hex(), 16))
        S.append(int(sig[0x20:0x40].hex(), 16))
        LEAKS.append(int(f.split('.vlny')[1], 16))

SAMPLES = len(LEAKS)

n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
F = GF(n)

LS = 16**10
B = next_prime(n)
kW = next_prime(2**n.bit_length() // LS)
FLS = F(LS)

M = block_matrix(QQ, [
    [n / kW,],
    [(matrix(S) * FLS**(-1)) / kW,],
    [((matrix(R) - matrix(LEAKS)) * FLS**(-1)) / kW,],
])

for row in M.LLL():
    if row[0] != 0:
        k0 = LS * int(abs(row[0]*kW)) + LEAKS[0]
        x = pow(S[0], -1, n) * (k0 - R[0]) % n
        break

print(f'{x = :x}')
x = x.to_bytes(32, 'big')

from Crypto.Cipher import AES

data = open(glob.glob(f"{REPO_PATH}/crypto/curveware/flag.txt*")[0], 'rb').read()

enc_flag = data[0x40:-0x10]
iv = data[-0x10:]

cipher = AES.new(x, AES.MODE_CBC, iv)

from Crypto.Util.Padding import unpad
print(unpad(cipher.decrypt(enc_flag), 16).decode())
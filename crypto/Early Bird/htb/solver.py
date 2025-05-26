import requests, sys, json, base64, time, re
from Crypto.Util.number import long_to_bytes
from Crypto.Signature.pss import MGF1
from Crypto.Hash import SHA512 as HF
from pwn import xor

def ceil_div(a, b):
    return a // b + (a % b > 0)

def floor_div(a, b):
    return a // b

# Step 1.
def _step_1(padding_oracle, n, e, c):
    f1 = 2
    while padding_oracle((pow(f1, e, n) * c) % n):
        f1 *= 2
    return f1


# Step 2.
def _step_2(padding_oracle, n, e, c, B, f1):
    f2 = floor_div(n + B, B) * f1 // 2
    while not padding_oracle((pow(f2, e, n) * c) % n):
        f2 += f1 // 2
    return f2


# Step 3.
def _step_3(padding_oracle, n, e, c, B, f2):
    mmin = ceil_div(n, f2)
    mmax = floor_div(n + B, f2)
    counter = 0
    while mmin < mmax:
        f = floor_div(2 * B, mmax - mmin)
        i = floor_div(f * mmin, n)
        f3 = ceil_div(i * n, mmin)
        if padding_oracle((pow(f3, e, n) * c) % n):
            mmax = floor_div(i * n + B, f3)
        else:
            mmin = ceil_div(i * n + B, f3)
            print(hex(mmin)[2:])
            # print(m.hex()[2:])
            # print('='*10)
        counter += 1
    return mmin


def attack(padding_oracle, n, e, c):
    k = ceil_div(n.bit_length(), 8)
    B = 2 ** (8 * (k - 1))
    assert 2 * B < n
    print("Executing step 1...")
    f1 = _step_1(padding_oracle, n, e, c)
    print("Executing step 2...")
    f2 = _step_2(padding_oracle, n, e, c, B, f1)
    print("Executing step 3...")
    m = _step_3(padding_oracle, n, e, c, B, f2)
    return m

def i2osp(i, k):
    return i.to_bytes(k, 'big')

def os2ip(self, s):
    return int.from_bytes(s, 'big')

def padding_oracle(n):
    while True:
        start = time.time()
        requests.post(f'{URL}/verify-token', json={
            'encrypted_token': base64.b64encode(i2osp(n, k)).decode()
        })
        end = time.time()
        total = end - start
        if total > 0.9:
            return True
        elif total < 0.29:
            return False
        time.sleep(0.1)

if __name__ == '__main__':
    URL = 'http://' + (sys.argv[1] if len(sys.argv) > 1 else 'localhost:1337')
    token = json.loads(base64.b64decode(requests.get(URL).cookies['token'].encode()).decode())
    n = int(token['n'], 16)
    k = n.bit_length() // 8
    e = 0x10001
    enc_pro_token = int(token['tok'], 16)
    assert padding_oracle(enc_pro_token)
    EM = i2osp(attack(padding_oracle, n, e, enc_pro_token), k)
    print(f'{EM = }')
    hLen = HF.digest_size
    maskedSeed = EM[1:hLen+1]
    maskedDB = EM[hLen+1:]
    seedMask = MGF1(maskedDB, hLen, HF)
    seed = xor(maskedSeed, seedMask)
    dbMask = MGF1(seed, k - hLen - 1, HF)
    DB = xor(maskedDB, dbMask)
    PS = DB[hLen:].split(b'\x01')[0]
    M = DB[hLen+len(PS)+1:]
    token = M.hex()
    print(f'{token = }')
    config = re.search(r'.*<token>(.+)</token>.*', requests.post(f'{URL}/download', json={ 'token': token }).content.decode())
    print(base64.b64decode(config.group(1)))
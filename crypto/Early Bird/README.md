![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>Early Bird</font>

​	2<sup>nd</sup> May 2025

​	Prepared By: `rasti`

​	Challenge Author: `rasti`

​	Difficulty: <font color=orange>Medium</font>

​	Classification: Official

# Synopsis

- `Early Bird` is a medium crypto challenge in which the player must analyze the provided Flask application and find the mistakes in the implementantion of RSA-OAEP decryption. The way the errors are checked causes a vulnerability that leads to a timing side-channel attack, which is also known as Manger's attack. By applying this attack, the player obtains the admin token and is able to download the admin configuration file.

## Description

- An exposed interface from Volnaya's internal config manager briefly went live on a forgotten subnet. While appearing mundane at first glance, it produces slightly different outputs depending on when and how it's queried. Circuitbreaker suspects someone built it with a hidden schedule in mind-likely to avoid internal audits.


## Skills Required

- Familiar with python source code analysis
- Good skill on researching and identifying about common cryptographic schemes
- Good knowledge of how RSA works
- Good understanding of how RSA-OAEP works
- Familiarity with identifying side-channel attacks in custom implementations
- Read RFC specifications

## Skills Learned

- Learn how to apply (and/or implement) Manger's attack
- Familiarise with careful reading of RFCs to avoid triggering vulnerabilities
- Identifying and exploiting software developer mistakes

# Enumeration

We are provided with a zip downloadable. Before proceeding to source code analysis, let us list its contents with the following command:

```
$ tree .

.
├── Dockerfile
├── build-docker.sh
├── challenge
│   └── application
│       ├── app.py
│       ├── crypto
│       │   └── verification.py
│       ├── requirements.txt
│       ├── static
│       │   ├── bg.jpg
│       │   ├── gohu.ttf
│       │   ├── main.css
│       │   └── volnaya.png
│       ├── templates
│       │   ├── base.html
│       │   ├── download.html
│       │   ├── home.html
│       │   └── verify_token.html
│       └── views.py
├── flag.txt
└── user-config.xml
```

At first glance, the file structure looks like a common setup for a Flask application. We are particularly interested in the cryptographic components of the application so let us start with analyzing `verification.py` and then moving on with `views.py` which implements all the endpoint handlers of the registered endpoints.

## Source Code Analysis

If we look at the `verification.py` script we can see that it consists of two core methods implementing RSA-related functionality. Namely, there is `encrypt` and `decrypt_and_verify` and some additional helper functions for data conversion and data hashing. An instance of the `LicenseVerificationScheme` class is initialized in `views.py`:

```python
scheme = None
@bp.before_request
def initialize_crypto():
    global scheme
    if not scheme:
        scheme = LicenseVerificationScheme(2048)
```

In the constructor, an RSA-2048 key is generated and some other variables are initialized that will be analyzed later.

```python
class LicenseVerificationScheme:
    def __init__(self, bits):
        self.key = RSA.generate(bits)
        self.L = str(self.key.n)[:72].encode()
        self.k = self.key.n.bit_length() // 8
        self.hLen = HF.digest_size
        self.PRO_TOKEN = token_bytes(64)
```

Let us analyze the `encrypt` function. Apparently, it does not encrypt the message $M$ using textbook RSA but there is some fancy padding added to the message. With some research, we are able to identify this scheme which is quite popular and known as `OAEP`. It's a non-deterministic padding scheme which means that padding the same message $M$ twice, will result in different padded messages. However, these padded messages are all deterministically decrypted to the original message $M$​.

The implementation of OAEP in the challenge is standard and implemented based on RFC 8017 specification. What stands out is the hash function used which is based on PBKDF2:

```python
from Crypto.Hash import SHA512 as HF

def H_verify(self, src, target):
    return target == self.H(src)

def H(self, m):
    salt = HF.new(str(self.key.n).encode()).hexdigest()
    return PBKDF2(m, salt, self.hLen, count=1_333_337, hmac_hash_module=HF)
```

At first glance, the number of iterations for each PBKDF2 call is relatively high but we will come back to this later. Let us analyze `views.py` and figure out what is the goal of the challenge.

First of all, when we launch to the Home Screen, the following code runs:

```python
@bp.route('/', methods=['GET'])
def home():
    resp = make_response(render_template("home.html"))
    if 'token' not in request.cookies:
        global scheme
        resp.set_cookie('token', b64encode(json.dumps({
            'timestamp': int(time.time()),
            'n': hex(scheme.key.n),
            'tok': scheme.encrypt(scheme.PRO_TOKEN).hex()
        }).encode()).decode())
    return resp
```

There is a cookie being set that consists of the current timestamp, the public modulus and an encrypted token, labeled as `PRO_TOKEN`. This is a random 64-byte string initialized at the constructor of `LicenseVerificationScheme`. From the `download` endpoint, we understand that the goal is to provide `PRO_TOKEN` in hex and download the admin config file which should contain the flag.

```python
bp.route('/download', methods=['GET', 'POST'])
def download():
    if request.method == 'POST':
        data = json.loads(request.data.decode())
        global scheme
        token = data['token']
        u = 'admin' if token == scheme.PRO_TOKEN.hex() else 'user'
        return send_file(
                    f'/{u}-config.xml',
                    mimetype='text/plain',
                    as_attachment=True,
                    download_name='config.xml'
                )
    return render_template("download.html")
```

The only endpoint we can use to extract useful information is `/verify-token`.

```python
@bp.route('/verify-token', methods=['GET', 'POST'])
def verify_token():
    if request.method == 'POST':
        if request.data:
            data = json.loads(request.data.decode())
            enc_token = data["encrypted_token"].encode()
        else:
            enc_token = request.form.get('encrypted_token', None).encode()

        if not enc_token:
            flash("Missing encrypted token!", "error")
            return redirect(url_for("views.verify_token"))
        try:
            decoded_token = b64decode(enc_token)
        except:
            flash("Invalid token format!", "error")
            return redirect(url_for("views.verify_token"))

        global scheme
        resp = scheme.decrypt_and_verify(decoded_token)
        if not resp["ok"]:
            flash(resp['error'], "error")
            return redirect(url_for("views.verify_token"))

        flash("Token verified!", "message")

        return redirect(url_for("views.verify_token"))

    return render_template("verify_token.html")
```

This serves as a testing endpoint in which we can enter our base64-encoded encrypted token, let the server decrypt it and get a reply whether the token was successfully verified or not.

# Solution

## Finding the vulnerability

By carefully reading section 7.1.2 in the RFC 8017 document, we can see that the challenge implementation is slightly modified. The important lines are highlighted below:

```python
if Y != 0 or not self.H_verify(self.L, DB[:self.hLen]) or self.os2ip(PS) != 0:
		return { "ok": False, "error": "decryption error" }
```

Quoting the final note of the section 7.1.2:

> Note: Care must be taken to ensure that an opponent cannot distinguish the different error conditions in Step 3.g

Indeed, an adversary cannot learn partial information about the decrypted message as the error string is exactly the same for any reason the error is thrown. However, the order in which the conditions are checked plays a crucial, and catastrophic, role in the way it is implemented. Let us first run `H` locally and count the time it takes to finish. We will use a SageMath shell as we have access to the IPython magic `%time`.

```python
sage: %time H_verify(b'test123'*20, b'this_is_a_test')
CPU times: user 1.03 s, sys: 6.33 ms, total: 1.04 s
Wall time: 1.04 s
False
```

Looks like it takes a second to finish.

Moreover, in a condition when there is a combination of logical OR conditions, their order matters. Take the following:

```python
sage: import time
sage: def slow_function():
....:     time.sleep(3)
....: 
sage: %time 1 == 1 or slow_function()
CPU times: user 10 µs, sys: 1 µs, total: 11 µs
Wall time: 13.1 µs
True
sage: %time 1 == 0 or slow_function()
CPU times: user 387 µs, sys: 1.44 ms, total: 1.83 ms
Wall time: 3.01 s
```

If the first OR condition is true, the whole condition is immediately evaluated to true, that is because $1\ \text{OR}\ \text{anything} = 1$. However, if it is false, the second condition is checked and in this toy example, it takes 3 seconds to finish. Back in our challenge, `slow_function` is actually `H_verify` as it takes a second to finish.

```python 
sage: %time 1 == 0 or H_verify(b'test123'*20, b'this_is_a_test')
CPU times: user 1.03 s, sys: 5.82 ms, total: 1.03 s
Wall time: 1.03 s
False
sage: %time 1 == 1 or H_verify(b'test123'*20, b'this_is_a_test')
CPU times: user 15 µs, sys: 1 µs, total: 16 µs
Wall time: 18.4 µs
True
```

This leads to a devastating vulnerability that enables us to perform a timing side-channel attack to learn partial information about the decrypted message. More specifically, if we send an encrypted token to `/verify-token` and the server takes a bit of time to reply, it means that $Y \neq 0$ is false and therefore $Y = 0$ which means that the message is correctly verified. Otherwise, it is not verified as $Y \neq 0$.

# Exploitation

In particular, this timing side-channel attack was found and implemented by Manger and therefore it is known as `Manger's Attack`. You can study more about this attack from the [original paper][1].

We can either go ahead and implement the attack ourselves to understand its internal workings, or use any online [implementation][2]. For this writeup, we choose the second option. The only thing we need to implement is `padding_oracle` which, according to the documentation, should return True if the padding is correct or False otherwise. In our case, we know the padding is correct if the server takes some time to respond.

```python
import time, requests, base64

URL = 'http://' + (sys.argv[1] if len(sys.argv) > 1 else 'localhost:1337')

def i2osp(i, k):
    return i.to_bytes(k, 'big')

def padding_oracle(n):
		while True:
        start = time.time()
        resp = requests.post(f'{URL}/verify-token', json={
            'encrypted_token': base64.b64encode(i2osp(n, k)).decode()
            })
        end = time.time()
        total = end - start
        if total > 0.9:
            return True
        elif total < 0.29:
            return False
        time.sleep(0.1)
```

***NOTE: You may have to adjust the hardcoded values 0.9 and 0.29 depending on your internet connection.***

Having recovered $EM$, we can go ahead and manually perform OAEP decoding to recover the actual token.

```python
token = json.loads(base64.b64decode(requests.get(URL).cookies['token'].encode()).decode())
n = int(token['n'], 16)
k = n.bit_length() // 8
e = 0x10001
enc_pro_token = int(token['tok'], 16)
EM = i2osp(attack(padding_oracle, n, e, enc_pro_token), k)
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
```

Finally, we can send the token to the `/download` endpoint and download the admin configuration file.

```python
import re
config = re.search(r'.*<token>(.+)</token>.*', requests.post(f'{URL}/download', json={ 'token': token }).content.decode())
print(base64.b64decode(config.group(1).encode()))
```

[1]: https://archiv.infsec.ethz.ch/education/fs08/secsem/manger01.pdf "Manger's Attack - Original Paper"
[2]: https://github.com/jvdsn/crypto-attacks/blob/708536c43fa632bb1278edd6651a30e8743e8d21/attacks/rsa/manger.py "Manger's Attack Implementation"



## Getting the flag

A final summary of all that was said above:

1. Find out that RSA-2048 is used for encryption/decryption of the access tokens.
2. The challenge implements RSA using the OAEP padding scheme.
3. After carefully reading the RFC about OAEP, we found out that the way the final if condition is implemented, it enables a timing side-channel attack that leaks partial information about the decrypted message.
4. This attack is also known as Manger's attack and eventually we are able to recover the entire token.
5. Having the token, we can send it to `/download` and download the admin config file.

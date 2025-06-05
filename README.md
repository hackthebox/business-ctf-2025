<p align='center'>
  <img src='assets/banner.png' alt="HTB">
</p>

# [**Challenges**](#challenges)

| Category | Name | Objective | Difficulty [⭐⭐⭐⭐⭐] |
| - | - | - | - |
| Pwn | [Power Greed](<pwn/Power Greed>) | Create a rop-chain through the gadgets of a statically linked binary to call execve("/bin/sh", 0, 0). | ⭐ |
| Pwn | [LiteServe](<pwn/LiteServe>) | Chained Buffer Overflow & Format string attack | ⭐⭐ |
| Pwn | [Null Assembler](<pwn/Null Assembler>) | Off-by-null to RCE | ⭐⭐ |
| Pwn | [Cyber Bankrupt](<pwn/Cyber Bankrupt>) | Trigger tcache double free and show heap base. Get a chunk which is overlapped by using tcache poisoning. Leak libc address. Get a chunk which is overlapped __free_hook and overwrite __free_hook to one gadget rce. | ⭐⭐⭐ |
| Pwn | [NeonCGI](<pwn/NeonCGI>) | .bss buffer overflow | ⭐⭐⭐⭐ |
| Reversing | [Industry Secret](<reversing/Industry Secret>) | ARM UART backdoor rev | ⭐⭐ |
| Reversing | [Scrambled Payload](<reversing/Scrambled Payload>) | VBScript deobfuscation | ⭐⭐ |
| Reversing | [TinyPlatformer](<reversing/TinyPlatformer>) | pyinstaller reversing | ⭐⭐ |
| Reversing | [EvilBox](<reversing/EvilBox>) | reversing backdoor in FOSS software | ⭐⭐⭐ |
| Reversing | [ShadowLabyrinth](<reversing/ShadowLabyrinth>) | C++ vm reversing | ⭐⭐⭐⭐ |
| Web | [Blackout Ops](<web/Blackout Ops>) | Bypassing multipart form validation & XSS via SVG | ⭐⭐ |
| Web | [Volnaya Forums](<web/Volnaya Forums>) | chaining Self XSS with Session Fixation via CRLF injection for account takeover. | ⭐⭐ |
| Web | [QuickBlog](<web/QuickBlog>) | Abuse stored XSS on a custom client-side markdown parser -> exfiltrate session cookie via DNS -> upload file to arbitrary path via path traversal -> trigger RCE on CherryPy session files via python pickle. | ⭐⭐⭐ |
| Web | [novacore](<web/novacore>) | Traefik API authentication bypass via CVE-2024-45410 => memory overflow on custom keystore implementation => cache poisoning => dom clobbering => client side path traversal => prototype pollution => unsafe eval call => CSP bypass => cookie exfiltration via undocumented feature => unrestricted file upload via path traversal => RCE via TAR/ELF polyglot file | ⭐⭐⭐⭐ |
| Crypto | [Transcoded](<crypto/Transcoded>) | Decode the flag with custom base64-based encoding scheme | ⭐ |
| Crypto | [Hidden Handshake](<crypto/Hidden Handshake>) | AES-CTR keystream reuse | ⭐⭐ |
| Crypto | [Phoenix Zero Trust](<crypto/Phoenix Zero Trust>) | Mersenne Twister randcrack | ⭐⭐ |
| Crypto | [Early Bird](<crypto/Early Bird>) | Manger's Timing Attack | ⭐⭐⭐ |
| Crypto | [Curveware](<crypto/Curveware>) | Custom ECDSA-like signature scheme with leaked nonce bits | ⭐⭐⭐⭐ |
| Forensics | [Phantom Check](<forensics/Phantom Check>) | Virtualization detection techniques used by attackers. | ⭐ |
| Forensics | [Smoke & Mirrors](<forensics/Smoke & Mirrors>) | Analyze the provided event logs and forensic artifacts to uncover how the attacker disabled or altered security features. | ⭐ |
| Forensics | [Ghost Thread](<forensics/Ghost Thread>) | Post-breach attack where malicious code injected into a legitimate process.  | ⭐⭐ |
| Forensics | [The Nexus Breach](<forensics/The Nexus Breach>) | PCAP file analysis containing network traffic related to an attack that targets a Nexus OSS instance. | ⭐⭐⭐ |
| Forensics | [Driver's Shadow](<forensics/Driver's Shadow>) | Identification and analysis of a memory only rootkit, loaded by a malicious udev backdoor rule. | ⭐⭐⭐⭐ |
| Hardware | [Echos Of Authority](<hardware/EchoesOfAuthority>) | Extract DTMF tones from a VOIP packet capture | ⭐⭐ |
| Hardware | [Volnayan Whisper](<hardware/VolnayanWhisper>) | Extract PDU-formatted SMS from USB traffic | ⭐⭐ |
| Hardware | [Sky Recon](<hardware/Sky Recon>) | Exploiting MAVLink protocol | ⭐⭐⭐ |
| Hardware | [Volnatek Motors](<hardware/VolnatekMotors>) | Smart car protocol exploitation | ⭐⭐⭐ |
| Hardware | [PhantomGate](<hardware/PhantomGate>) | Reverse engineering firmware and cryptographic primitives | ⭐⭐⭐⭐ |
| Blockchain | [Enlistment](<blockchain/Enlistment>) | Compute an expected proof hash | ⭐ |
| Blockchain | [Spectral](<blockchain/Spectral>) | Exploit incorrect reentrancy guards | ⭐⭐ |
| Blockchain | [Blockout](<blockchain/Blockout>) | TODO | ⭐⭐⭐ |
| ICS | [Whispers](<ics/whispers>) | Extracting Wireshark TCP streams | ⭐ |
| ICS | [Floody](<ics/floody>) | Understanding OPC UA protocol basics | ⭐⭐ |
| ICS | [Heat Plan](<ics/heatplan>) | Manipulating PLC data | ⭐⭐ |
| ICS | [Gridcryp](<ics/Gridcryp>) | Manipulating ICS variables with encryption | ⭐⭐⭐ |
| AI/ML | [External Affairs](<aiml/External Affairs>) | prompt injection to manipulate AI response | ⭐⭐ |
| AI/ML | [Loyalty Survey](<aiml/Loyalty Survey>) | Agentic AI Hijacking with prompt injection | ⭐⭐ |
| AI/ML | [TrynaSob Ransomware](<aiml/TrynaSob Ransomware>) | prompt injection to leak prompt instructions | ⭐⭐ |
| AI/ML | [Doctrine Studio](<aiml/Doctrine Studio>) | prompt injection and Agentic AI tool misuse to exploit a file read vulnerability | ⭐⭐⭐ |
| AI/ML | [Power Supply](<aiml/Power Supply>) | prompt injection and Agentic AI tool misuse to exfiltrate password from the database | ⭐⭐⭐ |
| Cloud | [Dashboarded](<cloud/Dashboarded>) | AWS metadata SSRF to credential stealing | ⭐ |
| Cloud | [Vault](<cloud/Vault>) | Improper S3 bucket misconfiguration with path traversal | ⭐ |
| Cloud | [TowerDump](<cloud/TowerDump>) | AWS Lambda misconfiguration leading to code injection and RCE | ⭐⭐ |
| Cloud | [EBS](<cloud/EBS>) | Overprivileged IAM role to privilege escalation | ⭐⭐⭐ |
| Cloud | [PipeDream](<cloud/PipeDream>) | Exploiting issues and misconfigurations in a DevOps environment | ⭐⭐⭐⭐ |
| Coding | [Threat Index](<coding/ThreatIndex>) | Substring Counting | ⭐ |
| Coding | [Honeypot](<coding/Honeypot>) | Tree Traversal | ⭐⭐ |
| Coding | [Triple Knock](<coding/TripleKnock>) | Parsing Timestamps & Sliding Window | ⭐⭐ |
| Coding | [Blackwire](<coding/Blackwire>) | Dynamic Programming | ⭐⭐⭐ |
| Coding | [Ghost Path](<coding/GhostPath>) | BFS, Tree Building & Efficient LCA | ⭐⭐⭐⭐ |
| Secure Coding | [phoenix sentinel](<securecoding/phoenix sentinel>) | Patching Cross Protocol SSRF | ⭐ |
| Secure Coding | [DarkWire](<securecoding/DarkWire>) | Patching ZipSlip in java application | ⭐⭐ |
| Secure Coding | [Atomic Protocol](<securecoding/atomic_protocol>) | Patching Race condition and File upload vulnerability in golang application | ⭐⭐⭐|
| Machine Learning | [Decision Gate](<ml/Decision-Gate>) | Reverse Engineering Model | ⭐⭐⭐|
| Machine Learning | [Neural Detonator](<ml/Neural-Detonator>) | Reverse-engineer a .keras machine learning model to uncover and decrypt an embedded payload | ⭐⭐⭐⭐|
| Machine Learning | [Uplink Artifact](<ml/Uplink-Artifact>) | Analyze 3D dataset | ⭐|
| Mobile | [Terminal](<mobile/terminal>) | Reverse the terminal code to unlock C2 mode and recover the encrypted flag | ⭐|


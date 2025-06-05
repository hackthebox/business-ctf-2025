![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left />Volnayan Whisper<font size='10'>

</font>

18<sup>th</sup> Apr 2025

Prepared By: `0xSn4k3000`

Challenge Author(s): `0xSn4k3000`

Difficulty: <font color='green'>easy</font>

<br><br>

# Synopsis (!)

- Analyze a PCAP containing USB modem traffic
- Identify AT commands used to interact with a GSM modem
- Extract a raw PDU-formatted SMS from a USB bulk transfer
- Decode the PDU to reveal the message content

## Description (!)

- Our Intel-team flagged an employee at one of our mines. We intercepted SMS messages from his laptop modem. Analyze the capture and determine if he's just a worker—or a spy hiding in plain sight.

## Skills Required (!)

- PCAP analysis
- USB protocol understanding
- GSM modem communication (AT commands)
- SMS PDU decoding
- Some light scripting (optional)

# Solution (!)

## Step 1: Analyze the capture file

We begin by opening the provided `capture.pcapng` file. Using `Wireshark`, we can inspect the captured packets. Once the file is open, we notice USB traffic present in the capture.

```
1	0.000000	host	1.6.0	USB	64	URB_CONTROL out
2	0.000108	1.6.0	host	USB	64	URB_CONTROL out
3	0.000181	host	1.6.0	USB	71	URB_CONTROL out
4	0.000332	1.6.0	host	USB	64	URB_CONTROL out
5	0.000428	host	1.6.2	USB/AT	67	URB_BULK out, Sent AT Command: AT
6	0.000449	1.6.2	host	USB	64	URB_BULK out
7	0.002204	1.6.2	host	USB/AT	68	URB_BULK in, Rcvd AT Command:   OK
8	0.002211	host	1.6.2	USB	64	URB_BULK in
9	5.006577	host	1.6.2	USB/AT	74	URB_BULK out, Sent AT Command: AT+CMGF=0
10	5.006620	1.6.2	host	USB	64	URB_BULK out
11	5.009622	1.6.2	host	USB/AT	68	URB_BULK in, Rcvd AT Command:   OK
12	5.009641	host	1.6.2	USB	64	URB_BULK in
13	10.015016	host	1.6.2	USB/AT	74	URB_BULK out, Sent AT Command: AT+CMGL=4
14	10.015080	1.6.2	host	USB	64	URB_BULK out
15	10.017674	1.6.2	host	USB/AT	68	URB_BULK in, Rcvd AT Command:   OK
16	10.017700	host	1.6.2	USB	64	URB_BULK in
17	11.035778	host	1.6.2	USB/AT	76	URB_BULK out, Sent AT Command: AT+CMGS=186
18	11.035837	1.6.2	host	USB	64	URB_BULK out
19	11.039066	1.6.2	host	USB/AT	68	URB_BULK in, Rcvd AT Command:   >
20	11.039090	host	1.6.2	USB	64	URB_BULK in
21	11.042478	host	1.6.2	USB	437	URB_BULK out
22	11.044264	1.6.2	host	USB	64	URB_BULK out
23	11.132084	1.6.2	host	USB/AT	80	URB_BULK in, Rcvd AT Command:   +CMGS: 0    OK
24	11.132113	host	1.6.2	USB	64	URB_BULK in
```

In USB communication, URB_BULK in and URB_BULK out refer to bulk transfer operations:

- URB_BULK out

This indicates that data is being sent from the host to the USB device. Bulk-out transfers are typically used to deliver large amounts of data that don’t require strict timing.

- URB_BULK in

This shows data being sent from the USB device back to the host. It’s used to receive responses or data streams from the device.

Bulk transfers are reliable and ensure data integrity, though they don’t guarantee timing—making them ideal for modem communication where accuracy is more important than speed.

One of the most interesting aspects of the traffic is the presence of AT commands. But what exactly are AT commands?

### AT Commands

AT (Attention) commands are set of modem instructions used to control GSM/3G/4G modules via serial communication. These commands allow users to perform various operations like setting SMS modes, reading messages, sending texts, and much more. In this capture, we can see commands such as `AT`, `AT+CMGF`, `AT+CMGL`, and `AT+CMGS`, which indicate initialization, setting message format, listing messages, and sending SMS respectively.

- `AT`

This is a basic command used to check if the modem is responsive. If the modem replies with OK, it means it’s ready to receive further instructions.

- `AT+CMGF=0`

This sets the SMS message format. A value of 0 means PDU mode (Protocol Data Unit), PDU is the raw binary format used to encode SMS messages in GSM networks. Unlike text mode (which is human-readable), PDU mode contains structured binary data with headers, addresses, timestamps, and encoded message content.

- `AT+CMGL=4`

This lists SMS messages stored on the device. The number 4 is a flag indicating the type of messages to list:

    4 = All messages (received, unread, read, etc.).

- `AT+CMGS=186`

This command initiates the process of sending an SMS. The 186 refers to the length (in bytes) of the message data to be sent in PDU format. After this, the modem responds with a `>` prompt, awaiting the actual message content. Once the message is sent, the modem replies with +CMGS: <msg_ref> and OK to confirm success.

The modem application first attempts to read SMS messages from the device, but the inbox appears to be empty. Shortly after, a message with a length of 186 bytes is sent from the host to the modem, indicating an outgoing SMS transmission.

## Step 2: Getting the message

If we inspect the first `URB_BULK` out packet sent after the modem prompt:

```
21	11.042478	host	1.6.2	USB	437	URB_BULK out
```

We observe a long string of hex-encoded data:

```
3131303030423931333133333333333333334637303030383030414330303530303036313030373930303643303036463030363130303634303032303030363930303645303037343030363530303732303036333030363530303730303037343030363530303634303032433030323030303438303035343030343230303742303036343030333330303333303037303030354630303331303036453030354630303335303036443030333530303744303032303030353430303638303036353030373930303237303037323030363530303230303037353030373330303639303036453030363730303230303036393030373430303230303037343030364630303230303036323030373930303730303036313030373330303733303032303030363430303635303037343030363530303633303037343030363930303646303036453030324530303230303034443030364630303732303036353030323030303733303036463030364630303645303032451a
```

When decoded, this hex string reveals a PDU (Protocol Data Unit) message:

```
11000B913133333333F7000800AC005000610079006C006F0061006400200069006E007400650072006300650070007400650064002C0020004800540042007B0064003300330070005F0031006E005F0035006D0035007D002000540068006500790027007200650020007500730069006E006700200069007400200074006F002000620079007000610073007300200064006500740065006300740069006F006E002E0020004D006F0072006500200073006F006F006E002E[]
```

Note that the hex string includes a newline character, which is not part of the actual PDU message. This newline should be removed before decoding, to avoid corrupting the message.

## Step 3: Decoding the PDU packet

Before we attempt to decode the PDU, it’s important to understand that there are three main types of SMS messages, each defined by its purpose and direction:

- `SMS-SUBMIT`

  - Direction: Mobile device → SMSC (More about SMSC below)
  - Purpose: Sending an SMS.
  - Description: This is used when a mobile device submits a message to the network for delivery to another user.

- `SMS-DELIVER`

  - Direction: SMSC → Mobile device
  - Purpose: Receiving an SMS.
  - Description: This type is used when the SMSC delivers a message to the recipient’s device.

- `SMS-STATUS-REPORT`

  - Direction: SMSC → Mobile device (usually in response to SMS-SUBMIT)
  - Purpose: Delivery status notification.
  - Description: Reports whether a previously submitted message was delivered successfully or failed.

The `SMSC` (Short Message Service Center) is a core component in any mobile network responsible for handling SMS (Short Message Service) messages. It's essentially the post office for text messages — it stores, forwards, converts, and delivers SMS messages between mobile devices.

Now that we understand the different SMS types, we can identify that the message we’re analyzing is of type SMS-SUBMIT.

To decode an SMS-SUBMIT PDU, you can use an online tool such as:

[Diafaan Online SMS-SUBMIT PDU Decoder](https://www.diafaan.com/sms-tutorials/gsm-modem-tutorial/online-sms-submit-pdu-decoder/)

Simply paste the PDU string into the input field, and the tool will decode the message content and header fields for you.

```
Text message
To: +13333333337
Message: Payload intercepted, HTB{XXXXXXXXXX} They're using it to bypass detection. More soon.
```

### Decoding with python

Python 2.7 includes a handy module called smspdu that can be used to decode SMS PDU strings directly from the command line. This can be especially useful for quickly inspecting message contents during analysis or debugging.

To decode a PDU using smspdu, simply run:

```bash
python2.7 -m smspdu 11000B913133333333F7000800AC005000610079006C006F0061006400200069006E007400650072006300650070007400650064002C0020004800540042007B0064003300330070005F0031006E005F0035006D0035007D002000540068006500790027007200650020007500730069006E006700200069007400200074006F002000620079007000610073007300200064006500740065006300740069006F006E002E0020004D006F0072006500200073006F006F006E002E
```

This will output a decoded view of the message, including the recipient, encoding, and the full human-readable text body.

```bash
tp_mti = 1 (SMS-SUBMIT)
sender = unknown
tp_rd = 0
tp_vpf = 2
tp_vp = 0
tp_rp = 0
tp_udhi = 0
tp_srr = 0
tp_mr = 0
tp_al = 11
tp_toa = 91 (International number; ISDN/telephone numbering plan (E.164/E.163))
(recipient) address = '13333333337'
tp_pid = 0x00 (Normal Case)
tp_dcs = 0x08 (Immedate Display, UCS2)
tp_udl = 172
tp_ud = "\x00P\x00a\x00y\x00l\x00o\x00a\x00d\x00 \x00i\x00n\x00t\x00e\x00r\x00c\x00e\x00p\x00t\x00e\x00d\x00,\x00 \x00H\x00T\x00B\x00{\x00d\x003\x003\x00p\x00_\x001\x00n\x00_\x005\x00m\x005\x00}\x00 \x00T\x00h\x00e\x00y\x00'\x00r\x00e\x00 \x00u\x00s\x00i\x00n\x00g\x00 \x00i\x00t\x00 \x00t\x00o\x00 \x00b\x00y\x00p\x00a\x00s\x00s\x00 \x00d\x00e\x00t\x00e\x00c\x00t\x00i\x00o\x00n\x00.\x00 \x00M\x00o\x00r\x00e\x00 \x00s\x00o\x00o\x00n\x00."
datestamp = 25041911382500
user_data = u"Payload intercepted, HTB{XXXXXXXX} They're using it to bypass detection. More soon."
user_data_headers = []
```

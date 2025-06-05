![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>
Echos Of Authority
</font>

9<sup>th</sup> May 2025

Prepared By: `0xSn4k3000`

Challenge Author(s): `0xSn4k3000`

Difficulty: <font color='green'>easy</font>

<br><br>

# Synopsis (!)

- Analyze a pcapng file with Wireshark.
- Analyze a VoIP call and extract the actual call sound.
- Getting the access key by analyzing the dtmf from the call.

## Description (!)

- Our Intel-Team has intercepted a VoIP call made by a high-ranking government official. During the call, the official accessed a secure government IVR (Interactive Voice Response) system, which requires a password to proceed. Your mission is to analyze the captured call and determine the password he entered.

## Skills Required (!)

- Knowledge of VoIP calls
- Knowledge of SIP and RTP protocol
- Knowledge of DTMF

# Solution (!)

## Step 1: Open the Capture File

We are provided with a `pcapng` file, which contains a network traffic capture of the intercepted VoIP call. You can open and analyze this file using a tool like `Wireshark`.

Here's a snippet of the capture:

```
1	0.000000000	172.17.0.1	172.17.0.2	SIP/SDP	529	Request: INVITE sip:1337@172.17.0.2:5060 |
2	0.001143931	172.17.0.2	172.17.0.1	SIP	502	Status: 100 Trying |
3	0.001423047	172.17.0.2	172.17.0.1	SIP/SDP	832	Status: 200 OK (INVITE) |
4	0.001893480	172.17.0.1	172.17.0.2	SIP	369	Request: ACK sip:1337@172.17.0.2:5060 |
5	0.502732305	172.17.0.2	172.17.0.1	RTP	214	PT=ITU-T G.711 PCMU, SSRC=0x3F993682, Seq=30575, Time=160, Mark
6	0.502769069	172.17.0.1	172.17.0.2	ICMP	242	Destination unreachable (Port unreachable)
7	0.523006431	172.17.0.2	172.17.0.1	RTP	214	PT=ITU-T G.711 PCMU, SSRC=0x3F993682, Seq=30576, Time=320
8	0.523033911	172.17.0.1	172.17.0.2	ICMP	242	Destination unreachable (Port unreachable)
9	0.543005067	172.17.0.2	172.17.0.1	RTP	214	PT=ITU-T G.711 PCMU, SSRC=0x3F993682, Seq=30577, Time=480
10	0.543032420	172.17.0.1	172.17.0.2	ICMP	242	Destination unreachable (Port unreachable)
11	0.562982284	172.17.0.2	172.17.0.1	RTP	214	PT=ITU-T G.711 PCMU, SSRC=0x3F993682, Seq=30578, Time=640
12	0.563009369	172.17.0.1	172.17.0.2	ICMP	242	Destination unreachable (Port unreachable)
13	0.583151172	172.17.0.2	172.17.0.1	RTP	214	PT=ITU-T G.711 PCMU, SSRC=0x3F993682, Seq=30579, Time=800
14	0.583186140	172.17.0.1	172.17.0.2	ICMP	242	Destination unreachable (Port unreachable)
15	0.603159922	172.17.0.2	172.17.0.1	RTP	214	PT=ITU-T G.711 PCMU, SSRC=0x3F993682, Seq=30580, Time=960
16	0.603187432	172.17.0.1	172.17.0.2	ICMP	242	Destination unreachable (Port unreachable)
17	0.622998924	172.17.0.2	172.17.0.1	RTP	214	PT=ITU-T G.711 PCMU, SSRC=0x3F993682, Seq=30581, Time=1120
18	0.642965916	172.17.0.2	172.17.0.1	RTP	214	PT=ITU-T G.711 PCMU, SSRC=0x3F993682, Seq=30582, Time=1280
19	0.662875761	172.17.0.2	172.17.0.1	RTP	214	PT=ITU-T G.711 PCMU, SSRC=0x3F993682, Seq=30583, Time=1440
20	0.683010186	172.17.0.2	172.17.0.1	RTP	214	PT=ITU-T G.711 PCMU, SSRC=0x3F993682, Seq=30584, Time=1600
```

Upon inspecting the traffic, you’ll notice two primary protocols being used:

1. `SIP (Session Initiation Protocol)`: SIP is a signaling protocol used to establish, manage, and terminate communication sessions involving voice, video, or messaging. In this capture, it handles the setup and teardown of the VoIP call.

2. `RTP (Real-time Transport Protocol)`: RTP is used for delivering real-time audio and video over IP networks. In this case, it carries the actual audio stream of the conversation.

## Step 2: Extract the Call

Wireshark is a powerful tool for network analysis, and it includes dedicated features for working with VoIP traffic. At the top menu bar, you'll find a Telephony tab that provides various tools for analyzing telephony protocols.

To view VoIP activity:

1. Navigate to `Telephony > VoIP` Calls.
2. A new window will appear, listing all VoIP calls detected in the capture.
3. In our case, there is a single call present in the traffic:

```
"Start Time","Stop Time","Initial Speaker","From","To","Protocol","Duration","Packets","State","Comments"
"0.000000","28.036433","172.17.0.1","sip:1337@172.17.0.1:5060","sip:1337@172.17.0.2:5060","SIP","00:00:28","6","COMPLETED","INVITE 200"

```

We can see that the call lasted approximately 28 seconds. To analyze the audio content:

- Click the Play Streams button to listen to the call directly within Wireshark.
- You can also choose to extract the audio by saving it as a .wav file.

## Step 3: Analyze the file.

Once you begin listening to the extracted call, you'll hear the IVR system prompting the caller to enter an **8-digit access key followed by a hash (`#`)**. Shortly after, a sequence of tones plays—these tones represent the digits pressed on the keypad.

These tones are known as `DTMF` signals, which stand for `Dual-Tone Multi-Frequency`.

### Dual-Tone Multi-Frequency (DTMF)

DTMF is a signaling system used in telephony to transmit digits or symbols over voice channels. Each key press on a phone generates a combination of two simultaneous audio tones—one from a low-frequency group and one from a high-frequency group. This pair uniquely identifies the key that was pressed.
DTMF Frequency Table:

|        | 1209 Hz | 1336 Hz | 1477 Hz | 1633 Hz |
| ------ | ------- | ------- | ------- | ------- |
| 697 Hz | 1       | 2       | 3       | A       |
| 770 Hz | 4       | 5       | 6       | B       |
| 852 Hz | 7       | 8       | 9       | C       |
| 941 Hz | \*      | 0       | #       | D       |

#### In-Band vs. Out-of-Band DTMF

There are two main methods for transmitting DTMF signals in VoIP systems:

- In-Band DTMF:
  The tones are transmitted directly within the RTP audio stream as actual audio signals—this is the case in our capture. You can hear these tones during playback and analyze them using audio tools or spectrograms.

- Out-of-Band DTMF:
  Instead of sending tones as audio, the keypad presses are transmitted as separate signaling information, typically using SIP INFO, RFC 2833, or RFC 4733 events. These are not audible in the audio stream and must be extracted from the SIP signaling packets.

In this challenge, we’re dealing with in-band DTMF, so your task will be to analyze the audio stream itself to determine the digits that were entered.

## Step 4: Extract the Access Key

Now that we have the audio file containing the DTMF tones, we can use a simple Python script to detect the digits pressed during the call.

We'll use the `soundfile` module to load the audio file and the `dtmf` module to detect the tones:

```python3
python3 -c "from dtmf import detect; import soundfile as sf; data, sr = sf.read('dtmf_audio.wav'); print([t.tone for t in detect(data, sr)])"
```

Here's what's happening:

- `soundfile` reads the `.wav` file and returns the audio data and sampling rate.
- `detect()` from the `dtmf` module processes the signal and returns the detected tones.
- We then extract the tone characters from the detection results.

When we run the script, we get a long list with many None values (background noise or silence), and eventually we see the detected tones:

```bash
[None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, Tone('1'), Tone('1'), None, Tone('1'), Tone('1'), Tone('1'), Tone('1'), Tone('1'), Tone('1'), Tone('1'), Tone('1'), Tone('1'), Tone('1'), Tone('1'), Tone('1'), Tone('1'), Tone('1'), Tone('1'), None, Tone('1'), None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), None, Tone('3'), Tone('3'), Tone('3'), Tone('3'), None, Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, Tone('5'), None, Tone('5'), None, None, None, None, Tone('5'), None, Tone('5'), None, None, None, Tone('5'), None, Tone('5'), None, Tone('5'), None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, Tone('1'), Tone('1'), Tone('1'), Tone('1'), Tone('1'), Tone('1'), Tone('1'), Tone('1'), None, Tone('1'), Tone('1'), Tone('1'), Tone('1'), None, Tone('1'), Tone('1'), Tone('1'), Tone('1'), Tone('1'), None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), None, None, Tone('3'), Tone('3'), Tone('3'), Tone('3'), None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), None, Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), Tone('3'), None, Tone('3'), Tone('3'), Tone('3'), None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, Tone('7'), Tone('7'), None, Tone('7'), Tone('7'), None, Tone('7'), Tone('7'), None, Tone('7'), Tone('7'), None, Tone('7'), Tone('7'), None, Tone('7'), Tone('7'), Tone('7'), None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, Tone('7'), Tone('7'), Tone('7'), Tone('7'), Tone('7'), Tone('7'), Tone('7'), Tone('7'), Tone('7'), None, None, Tone('7'), Tone('7'), Tone('7'), Tone('7'), Tone('7'), Tone('7'), Tone('7'), Tone('7'), None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, Tone('#'), Tone('#'), Tone('#'), Tone('#'), Tone('#'), Tone('#'), Tone('#'), Tone('#'), None, Tone('#'), Tone('#'), Tone('#'), Tone('#'), Tone('#'), Tone('#'), Tone('#'), Tone('#'), Tone('#')]
```

Ignoring the trailing #, the actual access key is: `13513377`

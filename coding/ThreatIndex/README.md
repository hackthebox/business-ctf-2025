![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />        <font size="10">Threat Index</font>

​        30<sup>th</sup> April 2025 / Document No. DYY.102.XX

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=green>Very Easy</font>

​        Classification: Official


# Synopsis

Threat Index is a very easy coding challenge, featuring basic substring counting.

## Skills Required

- Basic coding skills

## Skills Learned

- Counting number of matching substrings

## Description

```
Volnayan APTs are exfiltrating data through TOR nodes, embedding attack signals in plain sight.
Your job is to scan each outbound stream and identify known malicious keywords linked to Operation Blackout.
Each keyword has a threat level — the more hits you find, the higher the danger.
Analyze the stream, tally the signals, and calculate the overall threat score.
```

## Technical Description

```
You are monitoring data streams exiting suspicious TOR nodes, believed to be part of the Empire of Volnaya’s covert APT infrastructure.
As Talion “Little Byte” Reyes you’ve been assigned to identify and evaluate indicators of compromise embedded in the exfiltrated traffic.

Your job is to scan each stream for high-risk keywords associated with known attack patterns linked to Operation Blackout.

Each keyword has a weight representing its severity, based on intelligence recovered from earlier breaches.
The more often a keyword appears — and the higher its weight - the greater the threat posed by that stream.
The data stream contains only lowercase letters and digits.

You must calculate the threat score of each stream using the formula:

threat score = Σ (occurrences of keyword × keyword weight)

Here is the list of all the keywords and their associated weight:

KEYWORD      -> WEIGHT
"scan"       -> 1
"response"   -> 2
"control"    -> 3
"callback"   -> 4
"implant"    -> 5
"zombie"     -> 6
"trigger"    -> 7
"infected"   -> 8
"compromise" -> 9
"inject"     -> 10
"execute"    -> 11
"deploy"     -> 12
"malware"    -> 13
"exploit"    -> 14
"payload"    -> 15
"backdoor"   -> 16
"zeroday"    -> 17
"botnet"     -> 18

30 <= data stream length <= 10^6

Example:

Input:
payloadrandompayloadhtbzerodayrandombytesmalware

Expected output:
60

Analyzing the data stream:
payloadrandompayloadhtbzerodayrandombytesmalware
^^^^^^^      ^^^^^^^   ^^^^^^^           ^^^^^^^
  15           15        17                13

Calculating the threat score:

threat score = 2 * 15 + 17 + 13 = 60
```

## Solving the challenge

We'll use Python3 to implement the solution for this coding problem. First, let's copy over the given keywords and weights into a dictionary, so we can access them easily:

```python
KEYWORD_WEIGHTS = {
  "scan": 1,
  "response": 2,
  "control": 3,
  "callback": 4,
  "implant": 5,
  "zombie": 6,
  "trigger": 7,
  "infected": 8,
  "compromise": 9,
  "inject": 10,
  "execute": 11,
  "deploy": 12,
  "malware": 13,
  "exploit": 14,
  "payload": 15,
  "backdoor": 16,
  "zeroday": 17,
  "botnet": 18,
}
```

Let's read the data stream and store it in a variable called `data`. We will also initialize a variable `ans` to 0, which will hold the final threat score.

```python
data = input()
ans = 0
```

Next up, we will simply iterate over the keys and values of the dictionary, counting the number of times a keyword appears in the data stream, multiplying by the keyword's associated weight:

```python
for keyword, weight in KEYWORD_WEIGHTS.items():
  keyword_count = data.count(keyword)
  ans += keyword_count * weight

print(ans)
```

Putting it all together and running the code, we get the flag!

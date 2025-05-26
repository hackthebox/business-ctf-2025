![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />        <font size="10">Blackwire</font>

​        30<sup>th</sup> April 2025 / Document No. DYY.102.XX

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=orange>Medium</font>

​        Classification: Official

# Synopsis

Blackwire is a medium coding challenge where players are tasked to work with a binary-encoded state machine hidden in a firmware binary. the task requires bit-level parsing, interpreting a transition table, and analyzing the opcode stream to determine how many valid execution paths could trigger a malicious logic bomb. Beneath the surface, it tests the player's ability to implement a dynamic programming solution that counts valid opcode subsequences.

## Skills Required

- Binary parsing
- Basic understanding of finite state machines

## Skills Learned

- Parsing structured binary data
- Dynamic programming approach

## Description

```
A corrupted firmware update hides a logic bomb buried deep within a regional power grid controller.
As Mara “Hexor” Bianchi, you must analyze the intercepted binary and identify how many distinct execution paths could arm the payload.
Each opcode matters — decode the state machine, and stop the bomb from reaching its final trigger.
```

## Technical Description

```
A firmware update to a regional power grid controller was intercepted hours after the breach containment at the edge router.
Task Force Phoenix believes this is the next phase of Operation Blackout — a logic bomb embedded deep within the binary.

Mara “Hexor” Bianchi has been assigned to reverse engineer the firmware, and her analysis reveals that the logic bomb operates as a finite state machine.
It starts at state 0, and transitions sequentially through states (0 → 1 → 2 → ... → T) until it reaches a final activation state — at which point the bomb is armed.

The intercepted firmware is a long binary string. The first part contains a transition table, which defines the valid transitions between states.

Each entry in the table is 20 bits long and is structured as follows:
- The first 12 bits represent the current state (S).
- The next 8 bits represent the 8-bit opcode that needs to be executed while in state S, to transition to state S+1.

The remaining part of the binary string contains a sequence of 8-bit opcodes that will be executed in order.
The logic bomb can only progress to the next state if the current state and the opcode match a valid transition in the table.
Crucially, encountering one of these opcodes does not force the bomb to advance to the next state — it merely provides the option to do so.

Your mission is to analyze the firmware and determine how many unique opcode execution paths could cause the logic bomb to progress from state 0 to its final state, by strictly advancing one state at a time.

The input has the following format:
The first line contains two integers, T and L.
T is the number of entries in the transition table, while L is the number of bits after the transition table.
After T transition table entries (T * 20 bits), the next L bits are the opcodes that will be executed.

3 <= T <= 4000
80 <= L <= 80000

(The answer always fits in a 64-bit unsigned integer.)

Example:

3 240
000000000010110010110000000000000110100000000000000101111000011010000111100011001011011010001010110011100110110001110111100001010001111011011100101100101111111001101110101111000111011110000111100000101111110001111110011011101101010100010101000110101100111011010010111101010001010100011010110011000111
Answer: 4

T = 3, L = 240

The 3 transition table entries are embedded in the first part of the data,
with each entry being 20 bits long:
"000000000010110010110000000000000110100000000000000101111000"

Decoding them, we get the transition table:
+----------------------------+
| Current    Needed    Next  |
| State   -> Opcode -> State |
+----------------------------+
* "00000000001011001011":
   ^^^^^^^^^^^^
     State S   ^^^^^^^^
                Opcode
  000000000010 (binary) = 2 (decimal)
  While in state S, and the needed opcode is executed, the logic bomb can transition to state S+1.
  State 2 -> 11001011 -> State 3 (Final State)
  When the logic bomb state machine is in state 2, and the opcode 11001011 is encountered it can transition to state 3, which in this case is the final state.

* "00000000000001101000":
  State 0 -> 01101000 -> State 1

* "00000000000101111000":
  State 1 -> 01111000 -> State 2

Next we have the remaining binary data, which are the opcodes that will be executed:
"011010000111100011001011011010001010110011100110110001110111100001010001111011011100101100101111111001101110101111000111011110000111100000101111110001111110011011101101010100010101000110101100111011010010111101010001010100011010110011000111"

These are the 4 possible execution paths that could lead the logic bomb to trigger:
(The binary data is cut into parts for easier visualization)
1) 
01101000 01111000 11001011 01101000 10101100 11100110
S0 -> S1 S1 -> S2 S2 -> S3
11000111 01111000 01010001 11101101 11001011 00101111
11100110 11101011 11000111 01111000 01111000 00101111
11000111 11100110 11101101 01010001 01010001 10101100
11101101 00101111 01010001 01010001 10101100 11000111

2)
01101000 01111000 11001011 01101000 10101100 11100110
S0 -> S1 S1 -> S2
11000111 01111000 01010001 11101101 11001011 00101111
                                    S2 -> S3
11100110 11101011 11000111 01111000 01111000 00101111
11000111 11100110 11101101 01010001 01010001 10101100
11101101 00101111 01010001 01010001 10101100 11000111

3)
01101000 01111000 11001011 01101000 10101100 11100110
S0 -> S1
11000111 01111000 01010001 11101101 11001011 00101111
         S1 -> S2                   S2 -> S3
11100110 11101011 11000111 01111000 01111000 00101111 
11000111 11100110 11101101 01010001 01010001 10101100
11101101 00101111 01010001 01010001 10101100 11000111

4)
01101000 01111000 11001011 01101000 10101100 11100110
                           S0 -> S1
11000111 01111000 01010001 11101101 11001011 00101111
         S1 -> S2                   S2 -> S3
11100110 11101011 11000111 01111000 01111000 00101111 
11000111 11100110 11101101 01010001 01010001 10101100
11101101 00101111 01010001 01010001 10101100 11000111

These are the only execution paths that allow the logic bomb to progress to its final state, therefore the answer is 4.
```

## Solving the challenge

The first part is parsing our input data.

```python
import sys
T, L = map(int, input().strip().split(' '))
```

Since the transition table is not in sequential order, we will initialize it with zeros and then populate the opcodes in the correct indices. We are reading in 12 bits that represent the current state, and 8 bits representing the opcode needed to advance to the next state.

```python
transitions = [0x00] * T
for _ in range(T):
  state = int(sys.stdin.read(12), 2)
  opcode =int(sys.stdin.read(8), 2)
  transitions[state] = opcode
```

Each transition is stored as `transitions[state] = opcode`, meaning that when the state machine is in state `state` and encounters the opcode `opcode`, it can move to state `state+1`.

Next up, parsing the opcode execution stream:

```python
opcode_exec_stream = []
for i in range(0, L, 8):
  opcode_exec_stream.append(int(sys.stdin.read(8), 2))

# length of opcode_exec_stream since we are using 8-bit opcodes
m = L // 8
```

Now, for the interesting part: actually solving the challenge. We will be using a dynamic programming approach to drastically decrease our solver's time complexity and simplify the process. Let us start with the basics.

### What is dynamic programming ?

Dynamic programming is a technique used in programming to solve problems by breaking them down into smaller overlapping subproblems, solving each of those just once, and storing their results.

You can think about it like caching your work. If we have already solved step 3, and need it again for step 7, we should reuse the solution instead of redoing all the work.

Now, how can it be applied to this challenge?

What the problem is really asking us to do, is to count the number of unique subsequences of the logic bomb execution path found in the entire opcode execution stream.

Given a list `[A, B, C, D]`, a subsequence is any list you can form by removing elements (or none) without changing the order:
* [A, B, D] = valid
* [A, D] = valid
* [C, A] = invalid

How dynamic programming helps here:
1. We start off with the first opcode
2. Check if it matches the first required transition
3. if yes, we have two choices:
* Use it and move to the next required transition
* Skip it and try again
4. If no, skip and move on
5. Repeat for every opcode in the stream

Doing this recursively would be very inefficient, as the number of possibilities grows rapidly. Instead, dynamic programming builds a table that records all this in a structured, efficient way.

The DP table:

```python
dp_table[i][j]
```

This means, how many ways are there to match the first `j` transitions using the first `i` opcodes ?

```python
dp_table[i][0] = 1
```

This is because there is exactly 1 way to match zero transitions - by skipping everything.

For each `dp_table[i][j]`, we look whether the current opcode matches the current required transition.

If it matches:

```python
dp_table[i][j] = dp_table[i - 1][j - 1] + dp_table[i - 1][j]
```

* `dp_table[i-1][j-1]` : We use this opcode to make progress
* `dp_table[i-1][j]` : We skip this opcode

If it doesn't match:

```python
dp_table[i][j] = dp_table[i-1][j]
```

* We can only skip it - it doesn't help us progress

Now, applying everything to our problem:

```python
# initializing
dp_table = [[0] * (T + 1) for _ in range(m + 1)]
for i in range(m + 1):
  dp_table[i][0] = 1

# filling the table
for i in range(1, m + 1):
  for j in range(1, T + 1):
    if opcode_exec_stream[i - 1] == transitions[j - 1]:
      dp_table[i][j] = dp_table[i - 1][j - 1] + dp_table[i - 1][j]
    else:
      dp_table[i][j] = dp_table[i - 1][j]
```

If we implemented everything correctly, `dp_table[m][T]` holds the answer to our problem.

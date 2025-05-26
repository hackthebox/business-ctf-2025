![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />        <font size="10">Triple Knock</font>

​        30<sup>th</sup> April 2025 / Document No. DYY.102.XX

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=green>Easy</font>

​        Classification: Official

# Synopsis

Triple Knock is an easy coding challenge, where the player has to parse formatted timestamps, organize shuffled data, and use a sliding window approach to optimally search through the data.

## Skills Required

- Basic coding skills

## Skills Learned

- Parsing formatted timestamps
- Sliding window technique

## Description

```
Stolen credentials are now being used in coordinated login attempts across critical systems.
As Nava “Sleuth” Patel, your mission is to analyze authentication logs and flag user accounts that are under active attack.
Track suspicious access patterns, uncover brute-force attempts, and isolate the targeted identities before access is breached.
```

## Technical Description

```
Following intel extracted from suspicious TOR traffic during Operation Blackout, you’ve uncovered a dump of leaked credentials linked to strategic user accounts.
Advanced Persistent Threat (APT) actors—believed to be working under Volnaya’s cyber division — are now actively attempting to use these credentials against high-value infrastructure.

As Nava “Sleuth” Patel, your task is to analyze shuffled login logs and identify user accounts being targeted.

The input begins with a single line containing two integers:
S — the number of log entries
N — the number of users

The next S lines each contain the following information, separated by spaces:
* A user ID (e.g., user_1)
* A timestamp in the format DD/MM HH:MM (The year is the same for all entries, and it is assumed that all months have 30 days)
* A login status in brackets: [success] or [failure]

Print a space-separated list of all user IDs that are flagged as targeted.
The list should be in increasing lexicographical order.

10 <= S <= 10^5
2 <= N <= 200

Example:

Input:
13 4
user_2 23/07 15:41 [success]
user_1 10/06 05:17 [failure]
user_3 20/04 13:53 [failure]
user_1 06/04 17:07 [success]
user_1 10/06 05:19 [failure]
user_3 18/11 10:32 [success]
user_1 12/08 11:52 [success]
user_1 10/06 05:25 [failure]
user_3 20/04 13:59 [failure]
user_3 24/02 22:44 [failure]
user_3 16/02 17:16 [success]
user_3 20/04 13:54 [failure]
user_3 21/11 11:44 [success]

Expected Output:
user_1 user_3

"user_1" and "user_3" each have made 3 failed login attempts within a 10 minute window.
```

## Solving the challenge

First, we parse the S and N integers in the first line of our data. We will also initialize a dictionary `user_times`; the keys will be the user_id string, and the value will be a list containing integers representing the timestamps of the failed login attemps.

```python
S, N = map(int, input().split(' '))

from collections import defaultdict
user_times = defaultdict(list)
```

```python
for _ in range(S):
  entry = input()
  if "failure" not in entry: continue
  entry = entry.split("[")[0].strip()
  user = entry.split(" ")[0]
  timestamp = " ".join(entry.split(" ")[1:])
  user_times[user].append(total_minutes(timestamp))
```

This is the function `total_minutes` that is used above, calculating the total minutes passed from date 01/01 00:00.

```python
def total_minutes(ts):
	# Parse day/month and hour:minute
	day_month, time = ts.split()
	day, month = map(int, day_month.split("/"))
	hour, minute = map(int, time.split(":"))
	# Total days since 01/01
	days = ((month-1) * 30) + day - 1  # -1 because 1/1 is day 0
	return (days * 24 * 60) + (hour * 60) + minute
```

Now, everything is set up for us to use a sliding window approach on each user, and determine whether they have three failed login attemps in a 10-minute window. We create a list called `targeted`, that will hold all user ids that are flagged as targeted.

```python
targeted = []
for user, times in user_times.items():
  times.sort()
  for i in range(len(times) - 2):
    if times[i + 2] - times[i] <= 10:
      targeted.append(int(user.replace("user_", "")))
      break
```

Note that we are appeninding only the numeric part of the user ID (e.g. `1` from `user_1`). This allows us to sort the list numerically before formatting the final output. 

```python
targeted.sort()
print(" ".join([f"user_{ID}" for ID in targeted]))
```

Putting it all together and running the code, we get the flag!

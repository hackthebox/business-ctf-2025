#!/usr/bin/env python3
from collections import defaultdict

def total_minutes(ts):
	# Parse day/month and hour:minute
	day_month, time = ts.split()
	day, month = map(int, day_month.split("/"))
	hour, minute = map(int, time.split(":"))
	# Total days since 01/01
	days = ((month-1) * 30) + day - 1  # -1 because 1/1 is day 0
	return (days * 24 * 60) + (hour * 60) + minute

def solve():
  S, N = map(int, input().split(' '))
  user_times = defaultdict(list)
  for _ in range(S):
    entry = input()
    if "failure" not in entry: continue
    entry = entry.split("[")[0].strip()
    user = entry.split(" ")[0]
    timestamp = " ".join(entry.split(" ")[1:])
    user_times[user].append(total_minutes(timestamp))

  targeted = []
  for user, times in user_times.items():
    times.sort()
    for i in range(len(times) - 2):
      if times[i + 2] - times[i] <= 10:
        targeted.append(int(user.replace("user_", "")))
        break

  targeted.sort()
  print(" ".join([f"user_{ID}" for ID in targeted]))

solve()